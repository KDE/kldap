/*
  This file is part of libkldap.
  Copyright (c) 2006 Sean Harmer <sh@theharmers.co.uk>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General  Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; see the file COPYING.LIB.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#include "ldapmodel.h"
#include "ldapmodel_p.h"
#include "ldapmodeltreeitem_p.h"
#include "ldapsearch.h"

#include <kdebug.h>

using namespace KLDAP;

LdapModel::LdapModel( QObject *parent )
  : QAbstractItemModel( parent ),
    m_d( new LdapModelPrivate( this ) )
{
  m_d->createConnections();
}

LdapModel::LdapModel( LdapConnection &connection, QObject *parent )
  : QAbstractItemModel( parent ),
    m_d( new LdapModelPrivate( this, connection ) )
{
  m_d->createConnections();

  // Populate items from the root object to that representing the baseDN
  m_d->populateRootToBaseDN();
}

LdapModel::~LdapModel()
{
  delete m_d;
}

void LdapModel::setConnection( LdapConnection &connection )
{
  m_d->setConnection( connection );

  // Refresh the model
  m_d->recreateRootItem();

  // Populate the root object by searching the baseDN
  m_d->populateRootToBaseDN();
}

QModelIndex LdapModel::index( int row, int col, const QModelIndex &parent ) const
{
  LdapModelTreeItem *parentItem;
  if ( !parent.isValid() ) {
    parentItem = m_d->rootItem();
  } else {
    parentItem = static_cast<LdapModelTreeItem*>( parent.internalPointer() );
  }

  LdapModelTreeItem *childItem = parentItem->child( row );
  if ( childItem ) {
    return createIndex( row, col, childItem );
  } else {
    return QModelIndex();
  }
}

QModelIndex LdapModel::parent( const QModelIndex &child ) const
{
  if ( !child.isValid() ) {
    return QModelIndex();
  }

  LdapModelTreeItem *childItem = static_cast<LdapModelTreeItem*>( child.internalPointer() );
  LdapModelTreeItem *parentItem = childItem->parent();

  if ( parentItem == m_d->rootItem() ) {
    return QModelIndex();
  }

  return createIndex( parentItem->row(), 0, parentItem );
}

QVariant LdapModel::data( const QModelIndex &index, int role ) const
{
  if ( !index.isValid() ) {
    return QVariant();
  }

  LdapModelTreeItem *item = static_cast<LdapModelTreeItem*>( index.internalPointer() );

  if ( role == Qt::DisplayRole ) {
    kDebug(5322) << "***** LdapModel::data(): rdn = " << item->data().dn().rdnString() << endl;
    return item->data().dn().rdnString();
  } else if ( role == Qt::ToolTipRole ) {
    /** \TODO Make the tooltips look nicer - perhaps themeable? */
    kDebug(5322) << "***** LdapModel::data(): Object = " << item->data().toString() << endl;
    return item->data().toString();
  }

  /** \TODO Include support for nice decorative icons dependent upon the objectClass + other role data. */

  return QVariant();
}

QVariant LdapModel::headerData( int /*section*/, Qt::Orientation orientation, int role ) const
{
  if ( orientation == Qt::Horizontal && role == Qt::DisplayRole ) {
    /** @TODO Hmm, what to do here? Override in proxymodels perhaps as could be "DN" or "Attribute". */
    return QString( "Distinguished Name" );
  }

  return QVariant();
}

Qt::ItemFlags LdapModel::flags( const QModelIndex &index ) const
{
  /** \TODO Read-only for now, make read-write upon request */
  if ( !index.isValid() ) {
    return Qt::ItemIsEnabled;
  }

  return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}

int LdapModel::columnCount( const QModelIndex &parent ) const
{
  LdapModelTreeItem *parentItem = parent.isValid()
                                  ? static_cast<LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
  return parentItem->columnCount();
}

int LdapModel::rowCount( const QModelIndex &parent ) const
{
  kDebug(5322) << "LdapModel::rowCount" << endl;
  if ( parent.column() > 0 ) {
    return 0;
  }

  const LdapModelTreeItem *item = parent.isValid()
                                  ? static_cast<const LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
  kDebug(5322) << "Parent (" << item->ldapObject().dn().toString() << ") has " << item->childCount() << " children" << endl;
  return item->childCount();
}

bool LdapModel::hasChildren( const QModelIndex &parent ) const
{
  // We always return true. This means that the branch expansion symbol will
  // always be drawn. However, once the user clicks on it, rowCount() will
  // get called and the view will not draw the expander if the item has no
  // children.
  const LdapModelTreeItem *item = parent.isValid()
                                  ? static_cast<const LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
  if ( !parent.isValid() || item->isPopulated() ) {
    return item->childCount() > 0;
  }
  return true;
}

bool LdapModel::canFetchMore( const QModelIndex &parent ) const
{
  const LdapModelTreeItem *item = parent.isValid()
                                  ? static_cast<const LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
  kDebug(5322) << "LdapModel::canFetchMore() : " << !item->isPopulated() << endl;
  return !item->isPopulated();
}

void LdapModel::fetchMore( const QModelIndex &parent )
{
  /** \TODO This should be altered to search for all attributes we can filter out those not required with a proxy model */
  kDebug(5322) << "LdapModel::fetchMore()" << endl;

  LdapModelTreeItem *parentItem = parent.isValid()
                                  ? static_cast<LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();

  // Search for the immediate children of parentItem.
  m_d->searchResults().clear();
  m_d->setSearchType( LdapModelPrivate::ChildObjects, parentItem );
  m_d->search( parentItem->data().dn(), LdapUrl::One, QString(),
               QStringList() << "dn" << "objectClass" );
  parentItem->setPopulated( true );
}

#include "ldapmodel.moc"
