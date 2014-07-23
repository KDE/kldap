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

#ifndef KLDAP_LDAPURL_H
#define KLDAP_LDAPURL_H

#include <QtCore/QMap>
#include <QtCore/QStringList>

#include <QUrl>

#include "ldapdn.h"
#include "kldap_export.h"

namespace KLDAP
{

/**
 * @short A special url class for LDAP.
 *
 * LdapUrl implements an RFC 2255 compliant LDAP Url parser, with minimal
 * differences. LDAP Urls implemented by this class has the following format:
 * ldap[s]://[user[:password]@]hostname[:port]["/" [dn ["?" [attributes]
 * ["?" [scope] ["?" [filter] ["?" extensions]]]]]]
 */
class KLDAP_EXPORT LdapUrl : public QUrl
{
public:

    /**
     * A class holding the extension name and state whether
     * the extension is critical.
     */
    typedef struct {
        QString value;
        bool critical;
    } Extension;

    /**
     * Describes the scope of the LDAP url.
     */
    typedef enum {
        Base,  ///< Only the same level as the url.
        One,   ///< The level of the url and the one below.
        Sub    ///< All levels below the url's level.
    } Scope;

    /**
     * Constructs an empty LDAP url.
     */
    LdapUrl();

    /**
     * Constructs a LDAP url from a KUrl @p url.
     */
    explicit LdapUrl(const QUrl &url);

    /**
     * Constructs a LDAP url from an other url.
     */
    LdapUrl(const LdapUrl &other);

    /**
     * Overwrites the values of the LDAP url with values
     * from an @p other url.
     */
    LdapUrl &operator=(const LdapUrl &other);

    /**
     * Destroys the LDAP url.
     */
    virtual ~LdapUrl();

    /**
     * Sets the @p dn part of the LDAP url.
     */
    void setDn(const LdapDN &dn);

    /**
     * Returns the dn part of the LDAP url.
     * This is equal to path() with the slash removed from the beginning.
     */
    LdapDN dn() const;

    /**
     * Sets the @p attributes part of the LDAP url.
     */
    void setAttributes(const QStringList &attributes);

    /**
     * Returns the attributes part of the LDAP url.
     */
    QStringList attributes() const;

    /**
     * Sets the scope part of the LDAP url.
     */
    void setScope(Scope scope);

    /**
     * Returns the scope part of the LDAP url.
     */
    Scope scope() const;

    /**
     * Sets the filter part of the LDAP url.
     */
    void setFilter(const QString &filter);

    /**
     * Returns the filter part of the LDAP url.
     */
    QString filter() const;

    /**
     * Returns whether the specified @p extension exists in the LDAP url.
     */
    bool hasExtension(const QString &extension) const;

    /**
     * Returns the specified @p extension.
     */
    Extension extension(const QString &extension) const;

    /**
     * Returns the specified @p extension.
     */
    QString extension(const QString &extension, bool &critical) const;

    /**
     * Sets the specified extension @p key with the value and criticality in @p extension.
     */
    void setExtension(const QString &key, const Extension &extension);

    /**
     * Sets the specified extension @p key with the @p value and criticality specified.
     */
    void setExtension(const QString &key, const QString &value, bool critical = false);

    /**
     * Sets the specified extension @p key with the @p value and criticality specified.
     */
    void setExtension(const QString &key, int value, bool critical = false);

    /**
     * Removes the specified @p extension.
     */
    void removeExtension(const QString &extension);

    /**
     * Updates the query component from the attributes, scope, filter and extensions.
     */
    void updateQuery();

    /**
     * Parses the query argument of the URL and makes it available via the
     * attributes(), extension(), filter() and scope() methods
     */
    void parseQuery();

private:
    class LdapUrlPrivate;
    LdapUrlPrivate *const d;
};

}

#endif
