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

#include "ldapmodeltreeitem_p.h"

#include <kdebug.h>

using namespace KLDAP;

LdapModelTreeItem::LdapModelTreeItem( LdapModelTreeItem *parent, const LdapObject &data )
  : m_childItems(),
    m_parent( parent ),
    m_itemData( data ),
    m_isPopulated( false )
{
  kDebug(5322) << "LdapModelTreeItem::LdapModelTreeItem() : Object =" << data.toString();
  if ( m_parent ) {
    m_parent->appendChild( this );
  }
}

LdapModelTreeItem::~LdapModelTreeItem()
{
  qDeleteAll( m_childItems );
}

void LdapModelTreeItem::appendChild( LdapModelTreeItem *pItem )
{
  m_childItems.append( pItem );
  setPopulated( true );
}

LdapModelTreeItem *LdapModelTreeItem::child( int row )
{
  return m_childItems.value( row );
}

LdapModelTreeItem *LdapModelTreeItem::parent()
{
  return m_parent;
}

int LdapModelTreeItem::childCount() const
{
  return m_childItems.count();
}

int LdapModelTreeItem::columnCount() const
{
  return 1;
}

const LdapObject &LdapModelTreeItem::data() const
{
  return m_itemData;
}

int LdapModelTreeItem::row() const
{
  if ( m_parent ) {
    return m_parent->m_childItems.indexOf( const_cast<LdapModelTreeItem*>( this ) );
  }
  return 0;
}

LdapObject &LdapModelTreeItem::ldapObject()
{
  return m_itemData;
}

const LdapObject &LdapModelTreeItem::ldapObject() const
{
  return m_itemData;
}

void LdapModelTreeItem::setLdapObject( const LdapObject &object )
{
  kDebug(5322) << "LdapModelTreeItem::setLdapObject() : Object =" << object.toString();
  m_itemData = object;
}
