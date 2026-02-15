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
 * \class KLDAPCore::LdapServer
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapServer
 *
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
     * Creates a new LDAP server object from an LDAP URL.
     * \param url the LDAP URL of the server
     */
    explicit LdapServer(const LdapUrl &url);

    /*!
     * Creates a new LDAP server object as a copy of another.
     * \param other the LDAP server object to copy
     */
    LdapServer(const LdapServer &other);

    /*!
     * Assigns the values from another LDAP server object to this object.
     * \param other the LDAP server object to assign
     * \return a reference to this object
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
     * \param host the host name to set
     */
    void setHost(const QString &host);

    /*!
     * Returns the host of the LDAP connection.
     * \return the host name
     */
    [[nodiscard]] QString host() const;

    /*!
     * Sets the port of the LDAP connection.
     * If no port is set, 389 is used as default.
     * \param port the LDAP port to set
     */
    void setPort(int port);

    /*!
     * Returns the port of the LDAP connection.
     * \return the port number
     */
    [[nodiscard]] int port() const;

    /*!
     * Sets the base DN of the LDAP connection.
     * \param baseDn the base DN to set
     */
    void setBaseDn(const LdapDN &baseDn);

    /*!
     * Returns the base DN of the LDAP connection.
     * \return the base DN
     */
    [[nodiscard]] LdapDN baseDn() const;

    /*!
     * Sets the user of the LDAP connection.
     * \param user the user name to set
     */
    void setUser(const QString &user);

    /*!
     * Returns the user of the LDAP connection.
     * \return the user name
     */
    [[nodiscard]] QString user() const;

    /*!
     * Sets the bind DN of the LDAP connection.
     * \param bindDn the bind DN to set
     */
    void setBindDn(const QString &bindDn);

    /*!
     * Returns the bind DN of the LDAP connection.
     * \return the bind DN
     */
    [[nodiscard]] QString bindDn() const;

    /*!
     * Sets the SASL realm of the LDAP connection.
     * \param realm the realm to set
     */
    void setRealm(const QString &realm);

    /*!
     * Returns the realm of the LDAP connection.
     * \return the realm
     */
    [[nodiscard]] QString realm() const;

    /*!
     * Sets the password of the LDAP connection.
     * \param password the password to set
     */
    void setPassword(const QString &password);

    /*!
     * Returns the password of the LDAP connection.
     * \return the password
     */
    [[nodiscard]] QString password() const;

    /*!
     * Sets the protocol version of the LDAP connection.
     * If no version is set, 3 is used as default.
     * \param version the protocol version to set
     */
    void setVersion(int version);

    /*!
     * Returns the protocol version of the LDAP connection.
     * \return the protocol version
     */
    [[nodiscard]] int version() const;

    /*!
     * Sets the security mode of the LDAP connection.
     * If no security is set, None is used as default.
     * \param mode the security mode to set
     */
    void setSecurity(Security mode);

    /*!
     * Returns the security mode of the LDAP connection.
     * \return the security mode
     */
    [[nodiscard]] Security security() const;

    /*!
     * Sets the authentication method of the LDAP connection.
     * If no authentication method is set, Anonymous is used as default.
     * \param authentication the authentication method to set
     */
    void setAuth(Auth authentication);

    /*!
     * Returns the authentication method of the LDAP connection.
     * \return the authentication method
     */
    [[nodiscard]] Auth auth() const;

    /*!
     * Sets the certificate requirement mode for TLS/SSL connections.
     * \param reqCert the certificate requirement mode to set
     */
    void setTLSRequireCertificate(TLSRequireCertificate reqCert);

    /*!
     * Returns the certificate requirement mode for TLS/SSL connections.
     * \return the certificate requirement mode
     */
    [[nodiscard]] TLSRequireCertificate tlsRequireCertificate() const;

    /*!
     * Sets the CA certificate file for TLS/SSL connections.
     * \param caCertFile the path to the CA certificate file
     */
    void setTLSCACertFile(const QString &caCertFile);

    /*!
     * Returns the CA certificate file used for TLS/SSL connections.
     * \return the CA certificate file path
     */
    [[nodiscard]] QString tlsCACertFile() const;

    /*!
     * Sets the SASL mechanism of the LDAP connection.
     * \param mech the SASL mechanism to set
     */
    void setMech(const QString &mech);

    /*!
     * Returns the SASL mechanism of the LDAP connection.
     * \return the SASL mechanism
     */
    [[nodiscard]] QString mech() const;

    /*!
     * Sets the timeout of the LDAP connection.
     * \param timeout the timeout in seconds
     */
    void setTimeout(int timeout);

    /*!
     * Returns the timeout of the LDAP connection.
     * \return the timeout in seconds
     */
    [[nodiscard]] int timeout() const;

    /*!
     * Sets the search scope of the LDAP connection.
     * \param scope the search scope to set
     */
    void setScope(LdapUrl::Scope scope);

    /*!
     * Returns the search scope of the LDAP connection.
     * \return the search scope
     */
    [[nodiscard]] LdapUrl::Scope scope() const;

    /*!
     * Sets the time limit of the LDAP connection.
     * \param limit the time limit in seconds
     */
    void setTimeLimit(int limit);

    /*!
     * Returns the time limit of the LDAP connection.
     * \return the time limit in seconds
     */
    [[nodiscard]] int timeLimit() const;

    /*!
     * Sets the size limit of the LDAP connection.
     * \param sizelimit the size limit
     */
    void setSizeLimit(int sizelimit);

    /*!
     * Returns the size limit of the LDAP connection.
     * \return the size limit
     */
    [[nodiscard]] int sizeLimit() const;

    /*!
     * Sets the page size of the LDAP connection.
     * \param size the page size
     */
    void setPageSize(int size);

    /*!
     * Returns the page size of the LDAP connection.
     * \return the page size
     */
    [[nodiscard]] int pageSize() const;

    /*!
     * Sets the filter string of the LDAP connection.
     * \param filter the filter string to set
     */
    void setFilter(const QString &filter);

    /*!
     * Returns the filter string of the LDAP connection.
     * \return the filter string
     */
    [[nodiscard]] QString filter() const;

    /*!
     * Sets the server parameters from an RFC2255 compliant LDAP URL.
     * \param url the LDAP URL to set
     */
    void setUrl(const LdapUrl &url);

    /*!
     * Returns the server parameters as an RFC2255 compliant LDAP URL.
     * The URL extensions which are supported:
     * Standard: bindname
     * KLDAP extensions: x-tls, x-version, x-sasl, x-mech, x-realm,
     * x-sizelimit, x-timelimit, x-pagesize, x-timeout
     * \return the LDAP URL
     */
    [[nodiscard]] LdapUrl url() const;

    /*!
     * Sets the completion weight for this server.
     * \param value the completion weight to set
     */
    void setCompletionWeight(int value);

    /*!
     * Returns the completion weight for this server.
     * \return the completion weight
     */
    [[nodiscard]] int completionWeight() const;

    /*!
     * Sets the list of activities for this server.
     * \param lst the list of activities
     */
    void setActivities(const QStringList &lst);

    /*!
     * Returns the list of activities for this server.
     * \return the list of activities
     */
    [[nodiscard]] QStringList activities() const;

    /*!
     * Sets whether Plasma Activities support is enabled.
     * \param enabled true to enable Plasma Activities
     */
    void setEnablePlasmaActivities(bool enabled);

    /*!
     * Returns whether Plasma Activities support is enabled.
     * \return true if Plasma Activities are enabled
     */
    [[nodiscard]] bool enablePlasmaActivities() const;

private:
    class LdapServerPrivate;
    std::unique_ptr<LdapServerPrivate> const d;
};
}
KLDAP_CORE_EXPORT QDebug operator<<(QDebug d, const KLDAPCore::LdapServer &t);
