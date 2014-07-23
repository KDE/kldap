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

#ifndef KLDAP_LDAPSERVER_H
#define KLDAP_LDAPSERVER_H

#include <QtCore/QString>

#include "ldapurl.h"
#include "ldapdn.h"
#include "kldap_export.h"

namespace KLDAP
{

/**
 * @short A class that contains LDAP server connection settings.
 *
 * This class holds various parameters that are needed to connect
 * to an LDAP server.
 */
class KLDAP_EXPORT LdapServer
{
public:
    /**
     * Creates an empty LDAP server object.
     */
    LdapServer();

    /**
     * Creates a new LDAP server object.
     *
     * @param url The LDAP url of the server.
     */
    LdapServer(const LdapUrl &url);

    /**
     * Creates a new LDAP server object from an @p other object.
     */
    LdapServer(const LdapServer &other);

    /**
     * Overwrites the values of the LDAP server object with
     * the values from an @p other object.
     */
    LdapServer &operator=(const LdapServer &other);

    /**
     * Destroys the LDAP server object.
     */
    virtual ~LdapServer();

    /**
     * Describes the encryption settings that can be used
     * for the LDAP connection.
     */
    typedef enum {
        None, ///< Do not use any encryption.
        TLS,  ///< Use TLS encryption.
        SSL   ///< Use SSL encryption.
    } Security;

    /**
     * Describes the authentication method that can be used
     * for the LDAP connection.
     */
    typedef enum {
        Anonymous,  ///< Do no authentication.
        Simple,     ///< Authenticate via login and password.
        SASL        ///< Azthenticate with the SASL framework.
    } Auth;

    /**
     * Clears all server settings.
     */
    void clear();

    /**
     * Sets the host of the LDAP connection.
     */
    void setHost(const QString &host);

    /**
     * Returns the host of the LDAP connection.
     */
    QString host() const;

    /**
     * Sets the port of the LDAP connection.
     * If not port is set, 389 is used as default.
     * @param port the LDAP port connection to set
     */
    void setPort(int port);

    /**
     * Returns the port of the LDAP connection.
     */
    int port() const;

    /**
     * Sets the @p baseDn of the LDAP connection.
     */
    void setBaseDn(const LdapDN &baseDn);

    /**
     * Returns the baseDn of the LDAP connection.
     */
    LdapDN baseDn() const;

    /**
     * Sets the @p user of the LDAP connection.
     */
    void setUser(const QString &user);

    /**
     * Returns the user of the LDAP connection.
     */
    QString user() const;

    /**
     * Sets the @p bindDn of the LDAP connection.
     */
    void setBindDn(const QString &bindDn);

    /**
     * Returns the bindDn of the LDAP connection.
     */
    QString bindDn() const;

    /**
     * Sets the @p realm of the LDAP connection.
     */
    void setRealm(const QString &realm);

    /**
     * Returns the realm of the LDAP connection.
     */
    QString realm() const;

    /**
     * Sets the @p password of the LDAP connection.
     */
    void setPassword(const QString &password);

    /**
     * Returns the password of the LDAP connection.
     */
    QString password() const;

    /**
     * Sets the protocol @p version of the LDAP connection.
     * If no version is set, 3 is used as default.
     * @param version the protocol version to set
     */
    void setVersion(int version);

    /**
     * Returns the protocol version of the LDAP connection.
     */
    int version() const;

    /**
     * Sets the security @p mode of the LDAP connection.
     * If no security is set, None is used as default.
     * @param mode the security mode to set
     */
    void setSecurity(Security mode);

    /**
     * Returns the security mode of the LDAP connection.
     */
    Security security() const;

    /**
     * Sets the @p authentication method of the LDAP connection.
     * If no authentication method is set, Anonymous is used as default.
     * @param authentication the authentication method to set
     */
    void setAuth(Auth authentication);

    /**
     * Returns the authentication method of the LDAP connection.
     */
    Auth auth() const;

    /**
     * Sets the @p mech of the LDAP connection.
     */
    void setMech(const QString &mech);

    /**
     * Returns the mech of the LDAP connection.
     */
    QString mech() const;

    /**
     * Sets the @p timeout of the LDAP connection.
     */
    void setTimeout(int timeout);

    /**
     * Returns the timeout of the LDAP connection.
     */
    int timeout() const;

    /**
     * Sets the search @p scope of the LDAP connection.
     */
    void setScope(LdapUrl::Scope scope);

    /**
     * Returns the search scope of the LDAP connection.
     */
    LdapUrl::Scope scope() const;

    /**
     * Sets the time @p limit of the LDAP connection.
     */
    void setTimeLimit(int limit);

    /**
     * Returns the time limit of the LDAP connection.
     */
    int timeLimit() const;

    /**
     * Sets the size @p limit of the LDAP connection.
     */
    void setSizeLimit(int sizelimit);

    /**
     * Returns the size limit of the LDAP connection.
     */
    int sizeLimit() const;

    /**
     * Sets the page @p size of the LDAP connection.
     */
    void setPageSize(int size);

    /**
     * Returns the page size of the LDAP connection.
     */
    int pageSize() const;

    /**
     * Sets the @p filter string of the LDAP connection.
     */
    void setFilter(const QString &filter);

    /**
     * Returns the filter string of the LDAP connection.
     */
    QString filter() const;

    /**
     * Sets the server parameters from an RFC2255 compliant LDAP @p url.
     */
    void setUrl(const LdapUrl &url);

    /**
     * Returns the server parameters as an RFC2255 compliant LDAP Url.
     * The URL extensions which are supported:
     * Standard: bindname
     * KLDAP extensions: x-tls, x-version, x-sasl, x-mech, x-realm,
     * x-sizelimit, x-timelimit, x-pagesize, x-timeout
     */
    LdapUrl url() const;

private:
    class LdapServerPrivate;
    LdapServerPrivate *const d;
};

}

#endif
