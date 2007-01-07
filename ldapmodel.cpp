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

#include <kdebug.h>

#include "ldapmodel.h"
#include "ldapmodel_p.h"
#include <kldap/ldapmodeltreeitem.h>
#include <kldap/ldapsearch.h>

using namespace KLDAP;

LdapModel::LdapModel( QObject* parent )
    : QAbstractItemModel( parent ),
      m_d( new LdapModelPrivate )
{
    createConnections();
}


LdapModel::LdapModel( LdapConnection& connection, QObject* parent )
    : QAbstractItemModel( parent ),
      m_d( new LdapModelPrivate( connection ) )
{
    createConnections();

    // Populate items from the root object to that representing the baseDN
    populateRootToBaseDN();
}


LdapModel::~LdapModel()
{
    if ( m_d )
        delete m_d;
}


void LdapModel::createConnections()
{
    connect( m_d->search(), SIGNAL( result( LdapSearch* ) ),
             this, SLOT( gotSearchResult( LdapSearch* ) ) );
    connect( m_d->search(), SIGNAL( data( LdapSearch*, const LdapObject& ) ),
             this, SLOT( gotSearchData( LdapSearch*, const LdapObject& ) ) );
}


void LdapModel::setConnection( LdapConnection& connection )
{
    m_d->setConnection( connection );

    // Refresh the model
    m_d->recreateRootItem();

    // Populate the root object by searching the baseDN
    populateRootToBaseDN();
}


QModelIndex LdapModel::index( int row, int col, const QModelIndex& parent ) const
{
    LdapModelTreeItem* parentItem;
    if ( !parent.isValid() )
        parentItem = m_d->rootItem();
    else
        parentItem = static_cast<LdapModelTreeItem*>( parent.internalPointer() );

    LdapModelTreeItem* childItem = parentItem->child( row );
    if ( childItem )
        return createIndex( row, col, childItem );
    else
        return QModelIndex();
}


QModelIndex LdapModel::parent( const QModelIndex& child ) const
{
    if ( !child.isValid() )
        return QModelIndex();

    LdapModelTreeItem* childItem = static_cast<LdapModelTreeItem*>( child.internalPointer() );
    LdapModelTreeItem* parentItem = childItem->parent();

    if ( parentItem == m_d->rootItem() )
        return QModelIndex();

    return createIndex( parentItem->row(), 0, parentItem );
}


QVariant LdapModel::data( const QModelIndex& index, int role ) const
{
    if ( !index.isValid() )
        return QVariant();

    LdapModelTreeItem* item = static_cast<LdapModelTreeItem*>( index.internalPointer() );

    if ( role == Qt::DisplayRole )
    {
        kDebug() << "***** LdapModel::data(): rdn = " << item->data().dn().rdnString() << endl;
        return item->data().dn().rdnString();
    }
    else if ( role == Qt::ToolTipRole )
    {
        /** \TODO Make the tooltips look nicer - perhaps themeable? */
        kDebug() << "***** LdapModel::data(): Object = " << item->data().toString() << endl;
        return item->data().toString();
    }

    /** \TODO Include support for nice decorative icons dependent upon the objectClass + other role data. */

    return QVariant();
}


QVariant LdapModel::headerData( int /*section*/, Qt::Orientation orientation, int role ) const
{
    if ( orientation == Qt::Horizontal && role == Qt::DisplayRole )
    {
        /** @TODO Hmm, what to do here? Override in proxymodels perhaps as could be "DN" or "Attribute". */
        return QString( "Distinguished Name" );
    }

    return QVariant();
}


Qt::ItemFlags LdapModel::flags( const QModelIndex& index ) const
{
    /** \TODO Read-only for now, make read-write upon request */
    if ( !index.isValid() )
        return Qt::ItemIsEnabled;

    return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}


int LdapModel::columnCount( const QModelIndex& parent ) const
{
    LdapModelTreeItem* parentItem = parent.isValid()
                                  ? static_cast<LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
    return parentItem->columnCount();
}


int LdapModel::rowCount( const QModelIndex& parent ) const
{
    kDebug() << "LdapModel::rowCount" << endl;
    if ( parent.column() > 0 )
        return 0;

    const LdapModelTreeItem* item = parent.isValid()
                                  ? static_cast<const LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
    kDebug() << "Parent (" << item->ldapObject().dn().toString() << ") has " << item->childCount() << " children" << endl;
    return item->childCount();
}


bool LdapModel::hasChildren( const QModelIndex& parent ) const
{
    // We always return true. This means that the branch expansion symbol will
    // always be drawn. However, once the user clicks on it, rowCount() will
    // get called and the view will not draw the expander if the item has no
    // children.
    const LdapModelTreeItem* item = parent.isValid()
                                  ? static_cast<const LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
    if ( !parent.isValid() || item->isPopulated() )
        return ( item->childCount() > 0 );
    return true;
}


bool LdapModel::canFetchMore( const QModelIndex& parent ) const
{
    const LdapModelTreeItem* item = parent.isValid()
                                  ? static_cast<const LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();
    kDebug() << "LdapModel::canFetchMore() : " << !item->isPopulated() << endl;
    return !item->isPopulated();
}


void LdapModel::fetchMore( const QModelIndex& parent )
{
    /** \TODO This should be altered to search for all attributes we can filter out those not required with a proxy model */
    kDebug() << "LdapModel::fetchMore()" << endl;

    LdapModelTreeItem* parentItem = parent.isValid()
                                  ? static_cast<LdapModelTreeItem*>( parent.internalPointer() )
                                  : m_d->rootItem();

    // Search for the immediate children of parentItem.
    m_d->searchResults().clear();
    m_d->setSearchType( LdapModelPrivate::ChildObjects, parentItem );
    m_d->search( parentItem->data().dn(), LdapUrl::One, QString(), QStringList() << "dn" << "objectClass" );
    parentItem->setPopulated( true );
}


void LdapModel::populateRootToBaseDN()
{
    kDebug() << "LdapModel::populateRootToBaseDN()" << endl;

    if ( m_d->baseDN().isEmpty() )
    {
        // Query the server for the base DN
        m_d->setSearchType( LdapModelPrivate::NamingContexts, m_d->rootItem() );
        m_d->search( LdapDN(), LdapUrl::Base, QString(), QStringList() << "namingContexts" );
        return;
    }

    // Start a search for the details of the baseDN object
    m_d->searchResults().clear();
    LdapModelTreeItem* searchItem = m_d->rootItem();
    m_d->setSearchType( LdapModelPrivate::BaseDN, searchItem );
    m_d->search( m_d->baseDN(), LdapUrl::Base, QString(), QStringList() << "dn" << "objectClass" );
}


void LdapModel::gotSearchResult( LdapSearch* )
{
    kDebug() << "LdapModel::gotSearchResult()" << endl;

    switch ( m_d->searchType() )
    {
        case LdapModelPrivate::NamingContexts:
        {
            // Set the baseDN
            QString baseDN;
            if ( !m_d->searchResults().isEmpty() &&
                m_d->searchResults().at( 0 ).hasAttribute( "namingContexts" ) )
            {
                baseDN = m_d->searchResults().at( 0 ).value( "namingContexts" );
                kDebug() << "Found baseDN = " << baseDN << endl;
            }
            m_d->setBaseDN( LdapDN( baseDN ) );

            // Flag that we are no longer searching for the baseDN
            m_d->setSearchType( LdapModelPrivate::NotSearching );

            // Populate the root item
            populateRootToBaseDN();

            break;
        }
        case LdapModelPrivate::BaseDN:
        {
            kDebug() << "Found details of the baseDN object. Creating objects down to this level." << endl;

            // Get the baseDN LdapObject
            LdapObject baseDNObj = m_d->searchResults().at( 0 );

            // How many levels of items do we need to create?
            int depth = baseDNObj.dn().depth();

            // Create items that represent objects down to the baseDN
            LdapModelTreeItem* parent = m_d->rootItem();
            LdapModelTreeItem* item = 0;
            for ( int i = 0; i < depth; i++ )
            {
                QString dn = m_d->baseDN().toString( i );
                kDebug() << "Creating item for DN :" << dn << endl;
                LdapObject obj( dn );
                item = new LdapModelTreeItem( parent, obj );
                parent = item;
            }

            // Store the search result
            item->setLdapObject( m_d->searchResults().at( 0 ) );

            // Flag that we are no longer searching
            m_d->setSearchType( LdapModelPrivate::NotSearching );
            //emit( layoutChanged() );

            break;
        }
        case LdapModelPrivate::ChildObjects:
        {
            kDebug() << "Found " << m_d->searchResults().size() << " child objects" << endl;

            // Create an index for the soon-to-be-a-parent item
            LdapModelTreeItem* parentItem = m_d->searchItem();
            int r = parentItem->row();
            QModelIndex parentIndex = createIndex( r, 0, parentItem );

            beginInsertRows( parentIndex, 0, m_d->searchResults().size() );
            for ( int i = 0; i < m_d->searchResults().size(); i++ )
            {
                LdapObject itemData = m_d->searchResults().at( i );
                LdapModelTreeItem* item = new LdapModelTreeItem( parentItem, itemData );
                if ( !item )
                    kDebug() << "Could not create LdapModelTreeItem" << endl;
            }

            // Flag that we are no longer searching
            m_d->setSearchType( LdapModelPrivate::NotSearching );

            endInsertRows();
            emit( layoutChanged() );

            break;
        }
        default:
            break;
    }
}


void LdapModel::gotSearchData( LdapSearch*, const LdapObject& obj )
{
    kDebug() << "LdapModel::gotSearchData()" << endl;
    //kDebug() << "Object:" << endl << obj.toString() << endl;
    m_d->searchResults().append( obj );
}

#include "ldapmodel.moc"
