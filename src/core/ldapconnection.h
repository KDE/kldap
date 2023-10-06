/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QString>
#include <memory>

#include "kldap_core_export.h"
#include "ldapserver.h"
#include "ldapurl.h"

namespace KLDAPCore
{
/**
 * @brief
 * This class represents a connection to an LDAP server.
 */
class KLDAP_CORE_EXPORT LdapConnection
{
public:
    enum SASL_Fields { SASL_Authname = 0x1, SASL_Authzid = 0x2, SASL_Realm = 0x4, SASL_Password = 0x8 };

    /** Constructs an LdapConnection object */
    LdapConnection();
    /** Constructs an LdapConnection with the parameters given in url */
    explicit LdapConnection(const LdapUrl &url);
    /** Constructs an LdapConnection with the parameters given in server */
    explicit LdapConnection(const LdapServer &server);

    ~LdapConnection();

    /**
     * Sets the connection parameters via the specified url. After this,
     * you need to call connect() to connect with the new parameters.
     * @param url the URL containing the connection parameters
     */
    void setUrl(const LdapUrl &url);
    /**
     * Returns the connection parameters which was specified with an LDAP Url
     * or a LdapServer structure.
     */
    const LdapServer &server() const;
    /**
     * Sets the connection parameters via the specified server structure. After
     * this, you need to call connect() to connect with the new parameters.
     * @param server the server object containing the connection parameters
     */
    void setServer(const LdapServer &server);

    /**
     * Sets up the connection parameters with creating a handle to the LDAP server.
     * Also sets sizelimit and timelimit and starts TLS if it is requested.
     * Returns 0 if successful, else returns an LDAP error code, and an error
     * string which is available via connectionError().
     */
    int connect();
    /**
     * Returns a translated error string if connect() failed.
     */
    [[nodiscard]] QString connectionError() const;
    /**
     *  Closes the LDAP connection.
     */
    void close();

    /** Sets the size limit for the connection.
     *  @param sizelimit the connection size limit to set
     */
    [[nodiscard]] bool setSizeLimit(int sizelimit);
    /** Returns the current size limit. */
    [[nodiscard]] int sizeLimit() const;

    /** Sets the time limit for the connection.
     *  @param timelimit the connection time limit to set
     */
    [[nodiscard]] bool setTimeLimit(int timelimit);
    /** Returns the current time limit. */
    [[nodiscard]] int timeLimit() const;

    /** Gets an option from the connection. The option value can be client
     * library specific, so avoid this function if possible
     * @param option the connection option to return
     * @param value the value of option to get
     */
    int getOption(int option, void *value) const;
    /** Sets an option in the connection. The option value can be client
     * library specific, so avoid this function if possible */
    int setOption(int option, void *value);

    /** Returns the LDAP error code from the last operation */
    [[nodiscard]] int ldapErrorCode() const;
    /** Returns the LDAP error string from the last operation */
    [[nodiscard]] QString ldapErrorString() const;
    /** Returns a translated error message from the specified LDAP error code */
    [[nodiscard]] static QString errorString(int code);

    /** Returns the SASL error string from the last SASL operation */
    [[nodiscard]] QString saslErrorString() const;

    /**
     * Returns the opaqe client-library specific LDAP object.
     * Avoid its usage if you can.
     */
    void *handle() const;

    /**
     * Returns the opaqe sasl-library specific SASL object.
     * Avoid its usage if you can.
     */
    void *saslHandle() const;

private:
    class LdapConnectionPrivate;
    std::unique_ptr<LdapConnectionPrivate> const d;

    Q_DISABLE_COPY(LdapConnection)
};
}
