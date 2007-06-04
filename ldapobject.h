/*
  This file is part of libkldap.
  Copyright (c) 2004-2006 Szombathelyi György <gyurco@freemail.hu>

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

#ifndef KLDAP_LDAPOBJECT_H
#define KLDAP_LDAPOBJECT_H

#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QString>

#include "ldapdn.h"
#include "kldap_export.h"

namespace KLDAP {

typedef QList<QByteArray> LdapAttrValue;
typedef QMap<QString,LdapAttrValue > LdapAttrMap;

/**
 * @brief
 * This class represents an LDAP Object
*/
class KLDAP_EXPORT LdapObject
{
  public:
    LdapObject();
    explicit LdapObject( const QString &dn );
    virtual ~LdapObject();

    LdapObject( const LdapObject &that );
    LdapObject &operator=( const LdapObject &that );

    /**
     * Returns the text presentation (LDIF format) of the object.
     */
    QString toString() const;

    /**
     * Clears the name and attributes of the object.
     */
    void clear();
    /**
     * Sets the Distinguished Name of the object.
     */
    void setDn( const LdapDN &dn );
    /**
     * Sets the Distinguished Name of the object.
     */
    void setDn( const QString &dn );
    /**
     * Sets the attributes and attribute values of the object.
     */
    void setAttributes( const LdapAttrMap &attrs );
    /**
     * Sets the given attribute values. If the given attribute not exists,
     * then it's created, if exists, it's overwritten.
     */
    void setValues( const QString &attributeName, const LdapAttrValue &values );
    /**
     * Adds the given value to the specified attribute. If the given attribute
     * not exists, then it's created.
     */
    void addValue( const QString &attributeName, const QByteArray &value );
    /**
     * Return the Distinguished Name of the object.
     */
    LdapDN dn() const;
    /**
     * Returns the attributes and their values.
     */
    const LdapAttrMap &attributes() const;
    /**
     * Returns all values of the attribute with the given name.
     */
    LdapAttrValue values( const QString &attributeName ) const;
    /**
     * Returns the first value of the attribute with the given name
     * or an empty byte array if the attribute does not exists.
     */
    QByteArray value( const QString &attributeName ) const;
    /**
     * Returns true if the given attributethe exists, false otherwise.
     */
    bool hasAttribute( const QString &attributeName ) const;

  private:
    class Private;
    QSharedDataPointer<Private> d;
};

typedef QList<LdapObject> LdapObjects;
}

#endif
