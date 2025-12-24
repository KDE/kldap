/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QString>

#include "kldap_core_export.h"
#include "ldapdn.h"
#include "ldapurl.h"

// clazy:excludeall=copyable-polymorphic

namespace KLDAPCore
{
/*!
 * \brief A class that contains LDAP server connection settings.
 *
 * This class holds various parameters that are needed to connect
 * to an LDAP server.
 */
class KLDAP_CORE_EXPORT LdapServer
{
public:
    /*!
     * Creates an empty LDAP server object.
     */
    LdapServer();

    /*!
     * Creates a new LDAP server object.
     *
     * \a url The LDAP url of the server.
     */
    explicit LdapServer(const LdapUrl &url);

    /*!
     * Creates a new LDAP server object from an \a other object.
     */
    LdapServer(const LdapServer &other);

    /*!
     * Overwrites the values of the LDAP server object with
     * the values from an \a other object.
     */
    LdapServer &operator=(const LdapServer &other);

    /*!
     * Destroys the LDAP server object.
     */
    ~LdapServer();

    /*!
     * Describes the encryption settings that can be used
     * for the LDAP connection.
     */
    using Security = enum {
        None, ///< Do not use any encryption.
        TLS, ///< Use TLS encryption.
        SSL ///< Use SSL encryption.
    };

    /*!
     * Describes the authentication method that can be used
     * for the LDAP connection.
     */
    using Auth = enum {
        Anonymous, ///< Do no authentication.
        Simple, ///< Authenticate via login and password.
        SASL ///< Azthenticate with the SASL framework.
    };

    /*!
     * Describes the certificate request and check behaviour
     * for TLS/SSL connections.
     */
    using TLSRequireCertificate = enum {
        TLSReqCertDefault, ///< Use system defaults
        TLSReqCertNever, ///< Do not require any certificates.
        TLSReqCertDemand, ///< Use LDAP_OPT_X_TLS_DEMAND.
        TLSReqCertAllow, ///< Use LDAP_OPT_X_TLS_ALLOW.
        TLSReqCertTry, ///< Use LDAP_OPT_X_TLS_TRY.
        TLSReqCertHard, ///< Use LDAP_OPT_X_TLS_HARD.
    };

    /*!
     * Clears all server settings.
     */
    void clear();

    /*!
     * Sets the host of the LDAP connection.
     */
    void setHost(const QString &host);

    /*!
     * Returns the host of the LDAP connection.
     */
    [[nodiscard]] QString host() const;

    /*!
     * Sets the port of the LDAP connection.
     * If not port is set, 389 is used as default.
     * \a port the LDAP port connection to set
     */
    void setPort(int port);

    /*!
     * Returns the port of the LDAP connection.
     */
    [[nodiscard]] int port() const;

    /*!
     * Sets the \a baseDn of the LDAP connection.
     */
    void setBaseDn(const LdapDN &baseDn);

    /*!
     * Returns the baseDn of the LDAP connection.
     */
    [[nodiscard]] LdapDN baseDn() const;

    /*!
     * Sets the \a user of the LDAP connection.
     */
    void setUser(const QString &user);

    /*!
     * Returns the user of the LDAP connection.
     */
    [[nodiscard]] QString user() const;

    /*!
     * Sets the \a bindDn of the LDAP connection.
     */
    void setBindDn(const QString &bindDn);

    /*!
     * Returns the bindDn of the LDAP connection.
     */
    [[nodiscard]] QString bindDn() const;

    /*!
     * Sets the \a realm of the LDAP connection.
     */
    void setRealm(const QString &realm);

    /*!
     * Returns the realm of the LDAP connection.
     */
    [[nodiscard]] QString realm() const;

    /*!
     * Sets the \a password of the LDAP connection.
     */
    void setPassword(const QString &password);

    /*!
     * Returns the password of the LDAP connection.
     */
    [[nodiscard]] QString password() const;

    /*!
     * Sets the protocol \a version of the LDAP connection.
     * If no version is set, 3 is used as default.
     * \a version the protocol version to set
     */
    void setVersion(int version);

    /*!
     * Returns the protocol version of the LDAP connection.
     */
    [[nodiscard]] int version() const;

    /*!
     * Sets the security \a mode of the LDAP connection.
     * If no security is set, None is used as default.
     * \a mode the security mode to set
     */
    void setSecurity(Security mode);

    /*!
     * Returns the security mode of the LDAP connection.
     */
    [[nodiscard]] Security security() const;

    /*!
     * Sets the \a authentication method of the LDAP connection.
     * If no authentication method is set, Anonymous is used as default.
     * \a authentication the authentication method to set
     */
    void setAuth(Auth authentication);

    /*!
     * Returns the authentication method of the LDAP connection.
     */
    [[nodiscard]] Auth auth() const;

    /*!
     * Sets the certificate require mode for TLS/SSL connections
     */
    void setTLSRequireCertificate(TLSRequireCertificate reqCert);

    /*!
     * Returns the certificate require mode for TLS/SSL connections
     */
    [[nodiscard]] TLSRequireCertificate tlsRequireCertificate() const;

    /*!
     * Sets the CA certificate file for TLS/SSL connections
     */
    void setTLSCACertFile(const QString &caCertFile);

    /*!
     * Returns the CA certificate file used for TLS/SSL connections.
     */
    [[nodiscard]] QString tlsCACertFile() const;

    /*!
     * Sets the \a mech of the LDAP connection.
     */
    void setMech(const QString &mech);

    /*!
     * Returns the mech of the LDAP connection.
     */
    [[nodiscard]] QString mech() const;

    /*!
     * Sets the \a timeout of the LDAP connection.
     */
    void setTimeout(int timeout);

    /*!
     * Returns the timeout of the LDAP connection.
     */
    [[nodiscard]] int timeout() const;

    /*!
     * Sets the search \a scope of the LDAP connection.
     */
    void setScope(LdapUrl::Scope scope);

    /*!
     * Returns the search scope of the LDAP connection.
     */
    [[nodiscard]] LdapUrl::Scope scope() const;

    /*!
     * Sets the time \a limit of the LDAP connection.
     */
    void setTimeLimit(int limit);

    /*!
     * Returns the time limit of the LDAP connection.
     */
    [[nodiscard]] int timeLimit() const;

    /*!
     * Sets the size \a limit of the LDAP connection.
     */
    void setSizeLimit(int sizelimit);

    /*!
     * Returns the size limit of the LDAP connection.
     */
    [[nodiscard]] int sizeLimit() const;

    /*!
     * Sets the page \a size of the LDAP connection.
     */
    void setPageSize(int size);

    /*!
     * Returns the page size of the LDAP connection.
     */
    [[nodiscard]] int pageSize() const;

    /*!
     * Sets the \a filter string of the LDAP connection.
     */
    void setFilter(const QString &filter);

    /*!
     * Returns the filter string of the LDAP connection.
     */
    [[nodiscard]] QString filter() const;

    /*!
     * Sets the server parameters from an RFC2255 compliant LDAP \a url.
     */
    void setUrl(const LdapUrl &url);

    /*!
     * Returns the server parameters as an RFC2255 compliant LDAP Url.
     * The URL extensions which are supported:
     * Standard: bindname
     * KLDAP extensions: x-tls, x-version, x-sasl, x-mech, x-realm,
     * x-sizelimit, x-timelimit, x-pagesize, x-timeout
     */
    [[nodiscard]] LdapUrl url() const;

    void setCompletionWeight(int value);
    [[nodiscard]] int completionWeight() const;

    void setActivities(const QStringList &lst);
    [[nodiscard]] QStringList activities() const;

    void setEnablePlasmaActivities(bool enabled);
    [[nodiscard]] bool enablePlasmaActivities() const;

private:
    class LdapServerPrivate;
    std::unique_ptr<LdapServerPrivate> const d;
};
}
KLDAP_CORE_EXPORT QDebug operator<<(QDebug d, const KLDAPCore::LdapServer &t);
