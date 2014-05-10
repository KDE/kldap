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
#include "ldapmodelnode_p.h"
#include "ldapsearch.h"

#include <qdebug.h>
#include <klocalizedstring.h>
#include <kglobal.h>

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

QModelIndex LdapModel::parent( const QModelIndex &child ) const
{
  if ( !child.isValid() ) {
    return QModelIndex();
  }

  LdapModelNode *childItem = static_cast<LdapModelNode*>( child.internalPointer() );
  LdapModelDNNode *parentItem = childItem->parent();

  if ( parentItem == m_d->rootNode() ) {
    return QModelIndex();
  }

  return createIndex( parentItem->row(), 0, parentItem );
}

QModelIndex LdapModel::index( int row, int col, const QModelIndex &parent ) const
{
  // Retrieve a pointer to the parent item
  LdapModelDNNode *parentItem;
  if ( !parent.isValid() ) {
    parentItem = m_d->rootNode();
  } else {
    parentItem = static_cast<LdapModelDNNode*>( parent.internalPointer() );
  }

  LdapModelNode *childItem = parentItem->child( row );
  if ( childItem ) {
    return createIndex( row, col, childItem );
  }
  qDebug() << "Could not create valid index for row =" << row << ", col =" << col;
  return QModelIndex();
}

QVariant LdapModel::data( const QModelIndex &index, int role ) const
{
  if ( !index.isValid() ) {
    return QVariant();
  }

  if ( role == Qt::DisplayRole ) {
    // This is what gets displayed by the view delegates.
    LdapModelNode *node = static_cast<LdapModelNode*>( index.internalPointer() );
    if ( node->nodeType() == LdapModelNode::DN ) {
      LdapModelDNNode* dn = static_cast<LdapModelDNNode*>( node );
      if ( index.column() == 0 ) {
        return dn->dn().rdnString();
      } else {
        return QVariant();
      }
    } else {
      LdapModelAttrNode* attr = static_cast<LdapModelAttrNode*>( node );
      if ( index.column() == 0 ) {
        return QVariant( attr->attributeName() );
      } else {
        return QVariant( QLatin1String( attr->attributeData().constData() ) );
      }
    }
  } else if ( role == NodeTypeRole ) {
    LdapModelNode* node = static_cast<LdapModelNode*>( index.internalPointer() );
    return QVariant( int( node->nodeType() ) );
  }

  /** \todo Include support for nice decorative icons dependent upon
      the objectClass + other role data. */
  /** \todo Include support for other roles as needed */

  return QVariant();
}

bool LdapModel::setData( const QModelIndex &index,
                         const QVariant &value,
                         int role )
{
  Q_UNUSED( index );
  Q_UNUSED( value );
  Q_UNUSED( role );
  return false;
}

QVariant LdapModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
  if ( orientation == Qt::Horizontal && role == Qt::DisplayRole ) {
    if ( section == 0 ) {
      return i18n( "Attribute" );
    } else {
      return i18n( "Value" );
    }
  }

  return QVariant();
}

Qt::ItemFlags LdapModel::flags( const QModelIndex &index ) const
{
  /** \TODO Read-only for now, make read-write upon request */
  if ( !index.isValid() ) {
    return Qt::ItemIsEnabled;
  }

  return Qt::ItemFlags( Qt::ItemIsEnabled | Qt::ItemIsSelectable );
}

int LdapModel::columnCount( const QModelIndex &parent ) const
{
  LdapModelDNNode *parentNode =
    parent.isValid() ? static_cast<LdapModelDNNode*>( parent.internalPointer() ) : m_d->rootNode();
  return parentNode->columnCount();
}

int LdapModel::rowCount( const QModelIndex &parent ) const
{
  if ( parent.column() > 0 ) {
    return 0;
  }

  const LdapModelDNNode *parentNode =
    parent.isValid() ? static_cast<LdapModelDNNode*>( parent.internalPointer() ) : m_d->rootNode();
  return parentNode->childCount();
}

bool LdapModel::hasChildren( const QModelIndex &parent ) const
{
  // We return true unless the item has been populated and we are able to do a definitive test
  const LdapModelNode *node = parent.isValid() ?
                              static_cast<const LdapModelNode*>( parent.internalPointer() ) :
                              m_d->rootNode();

  if ( node->nodeType() != LdapModelNode::DN ) {
    return false;
  }

  const LdapModelDNNode* parentNode = static_cast<const LdapModelDNNode*>( node );
  if ( !parent.isValid() || parentNode->isPopulated() ) {
    return parentNode->childCount() > 0;
  }
  return true;
}

bool LdapModel::canFetchMore( const QModelIndex &parent ) const
{
  const LdapModelDNNode *parentNode =
    parent.isValid() ? static_cast<LdapModelDNNode*>( parent.internalPointer() ) : m_d->rootNode();
  return !parentNode->isPopulated();
}

void LdapModel::fetchMore( const QModelIndex &parent )
{
  LdapModelDNNode *parentNode =
    parent.isValid() ? static_cast<LdapModelDNNode*>( parent.internalPointer() ) : m_d->rootNode();

  // Search for the immediate children of parentItem.
  m_d->searchResults().clear();
  m_d->setSearchType( LdapModelPrivate::ChildObjects, parentNode );
  m_d->search( parentNode->dn(),  // DN to search from
               LdapUrl::One,      // What to search
               QString() );       // Attributes to retrieve
  parentNode->setPopulated( true );
}

bool LdapModel::insertRows( int row, int count,
                            const QModelIndex &parent )
{
  Q_UNUSED( row );
  Q_UNUSED( count );
  Q_UNUSED( parent );
  return false;
}

bool LdapModel::removeRows( int row, int count,
                            const QModelIndex &parent )
{
  Q_UNUSED( row );
  Q_UNUSED( count );
  Q_UNUSED( parent );
  return false;
}

void LdapModel::sort( int column, Qt::SortOrder order )
{
  Q_UNUSED( column );
  Q_UNUSED( order );
}

Qt::DropActions LdapModel::supportedDropActions() const
{
  return Qt::MoveAction;
}

QMimeData *LdapModel::mimeData( const QModelIndexList &indexes ) const
{
  Q_UNUSED( indexes );
  return 0;
}

bool LdapModel::dropMimeData( const QMimeData *data, Qt::DropAction action,
                              int row, int column, const QModelIndex &parent )
{
  /** \todo Implement drag and drop for LdapModel */
  Q_UNUSED( data );
  Q_UNUSED( action );
  Q_UNUSED( row );
  Q_UNUSED( column );
  Q_UNUSED( parent );
  return false;
}

bool LdapModel::hasChildrenOfType( const QModelIndex &parent, LdapDataType type ) const
{
  // Map from LdapDataType to our internal NodeType
  LdapModelNode::NodeType nodeType;
  switch ( type ) {
    case Attribute:
      nodeType = LdapModelNode::Attr;
      break;

    case DistinguishedName:
    default:
      nodeType = LdapModelNode::DN;
      break;
  }

  const LdapModelNode *node = parent.isValid() ?
                              static_cast<const LdapModelNode*>( parent.internalPointer() ) :
                              m_d->rootNode();

  const LdapModelDNNode* parentNode = static_cast<const LdapModelDNNode*>( node );
  if ( !parent.isValid() || parentNode->isPopulated() ) {
    // Check to see if the parent has any children of the specified type
    const QList<LdapModelNode*>& children = parentNode->children();
    foreach ( LdapModelNode *child, children ) {
      if ( child->nodeType() == nodeType ) {
        return true;
      }
    }

    // Either there are no children or only children of a different type
    return false;
  }

  // If the node is not populated or is the root node (invalid), then return
  // true to be on the safe side.
  return true;
}

void LdapModel::revert()
{

}

bool LdapModel::submit()
{
  return false;
}

#include "moc_ldapmodel.cpp"
