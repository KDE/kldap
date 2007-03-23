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

#ifndef KLDAP_LDAPMODELTREEITEM_H
#define KLDAP_LDAPMODELTREEITEM_H

#include <QtCore/QList>
#include <QtCore/QVariant>

#include "ldapobject.h"
#include "kldap.h"

namespace KLDAP {

/**
 * @internal
 */
class LdapModelTreeItem
{
  public:
    explicit LdapModelTreeItem( LdapModelTreeItem *parent = 0,
                                const LdapObject &data = LdapObject() );
    ~LdapModelTreeItem();

    void appendChild( LdapModelTreeItem *pItem );
    LdapModelTreeItem *child( int row );
    LdapModelTreeItem *parent();
    int childCount() const;
    int columnCount() const;
    const LdapObject &data() const;
    int row() const;

    LdapObject &ldapObject();
    const LdapObject &ldapObject() const;
    void setLdapObject( const LdapObject &object );

    void setPopulated( bool b ) { m_isPopulated = b; }
    bool isPopulated() const { return m_isPopulated; }

  private:
    QList<LdapModelTreeItem*> m_childItems;
    LdapModelTreeItem *m_parent;
    LdapObject m_itemData;
    bool m_isPopulated;
};

}

#endif
