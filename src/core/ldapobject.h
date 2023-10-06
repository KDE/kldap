/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QList>
#include <QMap>
#include <QSharedDataPointer>
#include <QString>
class LdapObjectPrivate;

#include "kldap_core_export.h"
#include "ldapdn.h"

// clazy:excludeall=copyable-polymorphic

namespace KLDAPCore
{
using LdapAttrValue = QList<QByteArray>;
using LdapAttrMap = QMap<QString, LdapAttrValue>;

/**
 * @brief
 * This class represents an LDAP Object
 */
class KLDAP_CORE_EXPORT LdapObject
{
public:
    LdapObject();
    explicit LdapObject(const QString &dn);
    ~LdapObject();

    LdapObject(const LdapObject &that);
    LdapObject &operator=(const LdapObject &that);

    /**
     * Returns the text presentation (LDIF format) of the object.
     */
    [[nodiscard]] QString toString() const;

    /**
     * Clears the name and attributes of the object.
     */
    void clear();
    /**
     * Sets the Distinguished Name of the object.
     */
    void setDn(const LdapDN &dn);
    /**
     * Sets the Distinguished Name of the object.
     */
    void setDn(const QString &dn);
    /**
     * Sets the attributes and attribute values of the object.
     */
    void setAttributes(const LdapAttrMap &attrs);
    /**
     * Sets the given attribute values. If the given attribute not exists,
     * then it's created, if exists, it's overwritten.
     * @param attributeName the attribute name for which to set values
     * @param values the values of attribute to set
     */
    void setValues(const QString &attributeName, const LdapAttrValue &values);
    /**
     * Adds the given value to the specified attribute. If the given attribute
     * not exists, then it's created.
     * @param attributeName the attribute for which to add a value
     * @param value the attribute  value to add
     */
    void addValue(const QString &attributeName, const QByteArray &value);
    /**
     * Return the Distinguished Name of the object.
     */
    [[nodiscard]] LdapDN dn() const;
    /**
     * Returns the attributes and their values.
     */
    const LdapAttrMap &attributes() const;
    /**
     * Returns all values of the attribute with the given name.
     */
    [[nodiscard]] LdapAttrValue values(const QString &attributeName) const;
    /**
     * Returns the first value of the attribute with the given name
     * or an empty byte array if the attribute does not exists.
     */
    [[nodiscard]] QByteArray value(const QString &attributeName) const;
    /**
     * Returns true if the given attributethe exists, false otherwise.
     */
    [[nodiscard]] bool hasAttribute(const QString &attributeName) const;

private:
    QSharedDataPointer<LdapObjectPrivate> d;
};

using LdapObjects = QList<LdapObject>;
}
