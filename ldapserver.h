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

namespace KLDAP {

/** This class holds various parameters about an LDAP server,
 * and the LDAP query parameters.
 */
class KLDAP_EXPORT LdapServer
{
  public:
    LdapServer();
    LdapServer( const LdapUrl &url );

    LdapServer( const LdapServer &that );
    LdapServer &operator= ( const LdapServer &that );

    virtual ~LdapServer();

    typedef enum {
      None, TLS, SSL
    } Security;
    typedef enum {
      Anonymous, Simple, SASL
    } Auth;

    /**
     * Clears all server settings.
     */
    void clear();

    QString host() const;
    int port() const;
    LdapDN baseDn() const;
    QString user() const;
    QString bindDn() const;
    QString realm() const;
    QString password() const;
    int version() const;
    Security security() const;
    Auth auth() const;
    QString mech() const;

    LdapUrl::Scope scope() const;
    int timeLimit() const;
    int sizeLimit() const;
    int pageSize() const;
    QString filter() const;

    void setHost( const QString &host );
    void setPort( int port );
    void setBaseDn( const LdapDN &baseDn );
    void setUser( const QString &user );
    void setBindDn( const QString &bindDn );
    void setRealm( const QString &realm );
    void setPassword( const QString &password );
    void setVersion( int version );
    void setSecurity( Security security );
    void setAuth( Auth auth );
    void setMech( const QString &mech );

    void setScope( LdapUrl::Scope scope );
    void setTimeLimit( int timelimit );
    void setSizeLimit( int sizelimit );
    void setPageSize( int pagesize );
    void setFilter( const QString &filter );

    /**
     * Returns the server parameters as an RFC2255 compliant LDAP Url.
     * The URL extensions which are supported:
     * Standard: bindname
     * KLDAP extensions: x-tls, x-version, x-sasl, x-mech, x-realm,
     * x-sizelimit, x-timelimit, x-pagesize
     */
    LdapUrl url() const;
    /**
     * Sets the server parameters from an RFC2255 compliant LDAP Url.
     */
    void setUrl( const LdapUrl &url );

  private:
    class LdapServerPrivate;
    LdapServerPrivate *const d;
};

}

#endif
