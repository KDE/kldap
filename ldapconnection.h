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

namespace KLDAP {

/**
 * @brief
 * This class represents a connection to an LDAP server.
 */
class KLDAP_EXPORT LdapConnection
{
  public:

    typedef enum SASL_Fields {
      SASL_Authname = 0x1,
      SASL_Authzid = 0x2,
      SASL_Realm = 0x4,
      SASL_Password = 0x8
    };

    typedef struct SASL_Credentials {
      int fields;
      QString authname;
      QString authzid;
      QString realm;
      QString password;
    };

    typedef int (SASL_Callback_Proc) ( SASL_Credentials &cred, void *data );

    typedef struct SASL_Data {
      SASL_Callback_Proc *proc;
      void *data;
      SASL_Credentials creds;
    };

    /** Constructs an LdapConnection object */
    LdapConnection();
    /** Constructs an LdapConnection with the parameters given in url */
    explicit LdapConnection( const LdapUrl &url );
    /** Constructs an LdapConnection with the parameters given in server */
    explicit LdapConnection( const LdapServer &server );

    virtual ~LdapConnection();

    /**
     * Sets the connection parameters via the specified url. After this,
     * you need to call connect() to connect with the new parameters.
     */
    void setUrl( const LdapUrl &url );
    /**
     * Sets the connection parameters via the specified server structure. After
     * this, you need to call connect() to connect with the new parameters.
     */
    void setServer( const LdapServer &server );
    /**
     * Connects to the specified LDAP server with the appropriate SSL/TLS
     * setting. Also sets sizelimit and timelimit.
     * Returns 0 if successful, else returns an LDAP error code, and an error
     * string which is available via connectionError().
     */
    int connect();
    /**
     * Returns a translated error string if connect() failed.
     */
    QString connectionError() const;
    /**
     * Binds to the LDAP server (authenticates), via simple/SASL method.
     * Returns 0 if successful, -0xff if the specified authentication method
     * is not available (the SASL library was not present during compiling),
     * an LDAP error code if other error occurred.
     */
    int bind( SASL_Callback_Proc *saslproc = 0, void *data = 0 );
    /**
     *  Closes the LDAP connection.
     */
    void close();

    /** Sets the size limit for the connection. */
    bool setSizeLimit( int sizelimit );
    /** Returns the current size limit. */
    int sizeLimit() const;

    /** Sets the time limit for the connection. */
    bool setTimeLimit( int timelimit );
    /** Returns the current time limit. */
    int timeLimit() const;

    /** Gets an option from the connection. The option value can be client
      * library specific, so avoid this function if possible */
    int getOption( int option, void *value ) const;
    /** Sets an option in the connection. The option value can be client
      * library specific, so avoid this function if possible */
    int setOption( int option, void *value );

    /** Returns the LDAP error code from the last operation */
    int ldapErrorCode() const;
    /** Returns the LDAP error string from the last operation */
    QString ldapErrorString() const;
    /** Returns a translated error code from the specified LDAP error code */
    static QString errorString( int code );

    /**
     * Returns the opaqe client-library specific LDAP object.
     * Avoid its usage if you can.
     */
    void *handle() const;

  private:
    class LdapConnectionPrivate;
    LdapConnectionPrivate *const d;

    Q_DISABLE_COPY( LdapConnection )
};

}

#endif
