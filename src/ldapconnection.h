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

#ifndef KLDAP_LDAPCONNECTION_H
#define KLDAP_LDAPCONNECTION_H

#include <QtCore/QString>

#include "ldapurl.h"
#include "ldapserver.h"
#include "kldap_export.h"

namespace KLDAP
{

/**
 * @brief
 * This class represents a connection to an LDAP server.
 */
class KLDAP_EXPORT LdapConnection
{
public:

    enum SASL_Fields {
        SASL_Authname = 0x1,
        SASL_Authzid = 0x2,
        SASL_Realm = 0x4,
        SASL_Password = 0x8
    };

    /** Constructs an LdapConnection object */
    LdapConnection();
    /** Constructs an LdapConnection with the parameters given in url */
    explicit LdapConnection(const LdapUrl &url);
    /** Constructs an LdapConnection with the parameters given in server */
    explicit LdapConnection(const LdapServer &server);

    virtual ~LdapConnection();

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
    QString connectionError() const;
    /**
     *  Closes the LDAP connection.
     */
    void close();

    /** Sets the size limit for the connection.
     *  @param sizelimit the connection size limit to set
     */
    bool setSizeLimit(int sizelimit);
    /** Returns the current size limit. */
    int sizeLimit() const;

    /** Sets the time limit for the connection.
     *  @param timelimit the connection time limit to set
     */
    bool setTimeLimit(int timelimit);
    /** Returns the current time limit. */
    int timeLimit() const;

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
    int ldapErrorCode() const;
    /** Returns the LDAP error string from the last operation */
    QString ldapErrorString() const;
    /** Returns a translated error message from the specified LDAP error code */
    static QString errorString(int code);

    /** Returns the SASL error string from the last SASL operation */
    QString saslErrorString() const;

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
    LdapConnectionPrivate *const d;

    Q_DISABLE_COPY(LdapConnection)
};

}

#endif
