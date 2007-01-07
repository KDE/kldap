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

#include "ldapmodel_p.h"
#include <kldap/ldapmodeltreeitem.h>
#include <kldap/ldapsearch.h>

#include <kdebug.h>

using namespace KLDAP;

LdapModel::LdapModelPrivate::LdapModelPrivate()
    : m_root( new LdapModelTreeItem ),
      m_search( new LdapSearch ),
      m_searchResultObjects(),
      m_baseDN(),
      m_searchType( NotSearching ),
      m_searchItem( 0 )
{
}


LdapModel::LdapModelPrivate::LdapModelPrivate( LdapConnection& connection )
    : m_root( new LdapModelTreeItem ),
      m_search( new LdapSearch( connection ) ),
      m_searchResultObjects(),
      m_baseDN(),
      m_searchType( NotSearching ),
      m_searchItem( 0 )
{
}


LdapModel::LdapModelPrivate::~LdapModelPrivate()
{
    if ( m_root )
        delete m_root;

    if ( m_search )
        delete m_search;
}


void LdapModel::LdapModelPrivate::setConnection( LdapConnection& connection )
{
    m_search->setConnection( connection );
}


bool LdapModel::LdapModelPrivate::search( const LdapDN& searchBase,
                               LdapUrl::Scope scope,
                               const QString& filter,
                               const QStringList& attributes,
                               int pagesize )
{
    return m_search->search( searchBase.toString(), scope, filter, attributes, pagesize );
}


void LdapModel::LdapModelPrivate::setSearchType( SearchType t, LdapModelTreeItem* item )
{
    kDebug() << "LdapModel::LdapModelPrivate::setSearchType() : item = " << item << endl;
    m_searchType = t;
    m_searchItem = item;
}


void LdapModel::LdapModelPrivate::recreateRootItem()
{
    kDebug() << "LdapModel::LdapModelPrivate::recreateRootItem()" << endl;
    if ( m_root )
    {
        delete m_root;
        m_root = 0;
    }
    m_root = new LdapModelTreeItem;
    kDebug() << "&m_root = " << &m_root << endl;
}
