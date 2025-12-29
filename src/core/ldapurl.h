/*
    This file is part of libkldap.
    SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QStringList>

#include <QUrl>

#include "kldap_core_export.h"
#include "ldapdn.h"

// clazy:excludeall=copyable-polymorphic

namespace KLDAPCore
{
/*!
 * \class KLDAPCore::LdapUrl
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapUrl
 *
 * \brief A special url class for LDAP.
 *
 * LdapUrl implements an RFC 2255 compliant LDAP Url parser, with minimal
 * differences. LDAP Urls implemented by this class has the following format:
 * ldap[s]://[user[:password]@]hostname[:port]["/" [dn ["?" [attributes]
 * ["?" [scope] ["?" [filter] ["?" extensions]]]]]]
 */
class KLDAP_CORE_EXPORT LdapUrl : public QUrl
{
public:
    /*!
     * A class holding the extension name and state whether
     * the extension is critical.
     */
    using Extension = struct {
        QString value;
        bool critical;
    };

    /*!
     * Describes the scope of the LDAP url.
     */
    using Scope = enum {
        Base, ///< Only the same level as the url.
        One, ///< The level of the url and the one below.
        Sub ///< All levels below the url's level.
    };

    /*!
     * Constructs an empty LDAP url.
     */
    LdapUrl();

    /*!
     * Constructs a LDAP url from a KUrl \a url.
     */
    explicit LdapUrl(const QUrl &url);

    /*!
     * Constructs a LDAP url from an other url.
     */
    LdapUrl(const LdapUrl &other);

    /*!
     * Overwrites the values of the LDAP url with values
     * from an \a other url.
     */
    LdapUrl &operator=(const LdapUrl &other);

    /*!
     * Destroys the LDAP url.
     */
    ~LdapUrl();

    /*!
     * Sets the \a dn part of the LDAP url.
     */
    void setDn(const LdapDN &dn);

    /*!
     * Returns the dn part of the LDAP url.
     * This is equal to path() with the slash removed from the beginning.
     */
    [[nodiscard]] LdapDN dn() const;

    /*!
     * Sets the \a attributes part of the LDAP url.
     */
    void setAttributes(const QStringList &attributes);

    /*!
     * Returns the attributes part of the LDAP url.
     */
    [[nodiscard]] QStringList attributes() const;

    /*!
     * Sets the scope part of the LDAP url.
     */
    void setScope(Scope scope);

    /*!
     * Returns the scope part of the LDAP url.
     */
    [[nodiscard]] Scope scope() const;

    /*!
     * Sets the filter part of the LDAP url.
     */
    void setFilter(const QString &filter);

    /*!
     * Returns the filter part of the LDAP url.
     */
    [[nodiscard]] QString filter() const;

    /*!
     * Returns whether the specified \a extension exists in the LDAP url.
     */
    [[nodiscard]] bool hasExtension(const QString &extension) const;

    /*!
     * Returns the specified \a extension.
     */
    [[nodiscard]] Extension extension(const QString &extension) const;

    /*!
     * Returns the specified \a extension.
     */
    [[nodiscard]] QString extension(const QString &extension, bool &critical) const;

    /*!
     * Sets the specified extension \a key with the value and criticality in \a extension.
     */
    void setExtension(const QString &key, const Extension &extension);

    /*!
     * Sets the specified extension \a key with the \a value and criticality specified.
     */
    void setExtension(const QString &key, const QString &value, bool critical = false);

    /*!
     * Sets the specified extension \a key with the \a value and criticality specified.
     */
    void setExtension(const QString &key, int value, bool critical = false);

    /*!
     * Removes the specified \a extension.
     */
    void removeExtension(const QString &extension);

    /*!
     * Updates the query component from the attributes, scope, filter and extensions.
     */
    void updateQuery();

    /*!
     * Parses the query argument of the URL and makes it available via the
     * attributes(), extension(), filter() and scope() methods
     */
    void parseQuery();

private:
    class LdapUrlPrivate;
    std::unique_ptr<LdapUrlPrivate> const d;
};
}
