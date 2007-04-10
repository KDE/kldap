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

#include "ldapserver.h"

#include <kdebug.h>

using namespace KLDAP;

class LdapServer::LdapServerPrivate
{
  public:
    QString mHost;
    int mPort;
    LdapDN mBaseDn;
    QString mUser;
    QString mBindDn;
    QString mRealm;
    QString mPassword;
    QString mMech;
    QString mFilter;
    int mTimeLimit, mSizeLimit, mVersion, mPageSize;
    Security mSecurity;
    Auth mAuth;
    LdapUrl::Scope mScope;
};

LdapServer::LdapServer()
  : d( new LdapServerPrivate )
{
  clear();
}

LdapServer::LdapServer( const LdapUrl &url )
  : d( new LdapServerPrivate )
{
  clear();

  setUrl( url );
}

LdapServer::LdapServer( const LdapServer &that )
  : d( new LdapServerPrivate )
{
  *d = *that.d;
}

LdapServer &LdapServer::operator= ( const LdapServer &that )
{
  if ( this == &that ) {
    return *this;
  }

  *d = *that.d;

  return *this;
}

LdapServer::~LdapServer()
{
  delete d;
}

void LdapServer::clear()
{
  d->mPort = 389;
  d->mHost = d->mUser = d->mBindDn = d->mMech = d->mPassword = QString();
  d->mSecurity = None;
  d->mAuth = Anonymous;
  d->mVersion = 3;
  d->mSizeLimit = d->mTimeLimit = d->mPageSize = 0;
}

QString LdapServer::host() const
{
  return d->mHost;
}

int LdapServer::port() const
{
  return d->mPort;
}

LdapDN LdapServer::baseDn() const
{
  return d->mBaseDn;
}

QString LdapServer::user() const
{
  return d->mUser;
}

QString LdapServer::bindDn() const
{
  return d->mBindDn;
}

QString LdapServer::realm() const
{
  return d->mRealm;
}

QString LdapServer::password() const
{
  return d->mPassword;
}

QString LdapServer::filter() const
{
  return d->mFilter;
}

LdapUrl::Scope LdapServer::scope() const
{
  return d->mScope;
}

int LdapServer::timeLimit() const
{
  return d->mTimeLimit;
}

int LdapServer::sizeLimit() const
{
  return d->mSizeLimit;
}

int LdapServer::pageSize() const
{
  return d->mPageSize;
}

int LdapServer::version() const
{
  return d->mVersion;
}

LdapServer::Security LdapServer::security() const
{
  return d->mSecurity;
}

LdapServer::Auth LdapServer::auth() const
{
  return d->mAuth;
}

QString LdapServer::mech() const
{
  return d->mMech;
}

void LdapServer::setHost( const QString &host )
{
  d->mHost = host;
}

void LdapServer::setPort( int port )
{
  d->mPort = port;
}

void LdapServer::setBaseDn( const LdapDN &baseDn )
{
  d->mBaseDn = baseDn;
}

void LdapServer::setUser( const QString &user )
{
  d->mUser = user;
}

void LdapServer::setBindDn( const QString &bindDn )
{
  d->mBindDn = bindDn;
}

void LdapServer::setRealm( const QString &realm )
{
  d->mRealm = realm;
}

void LdapServer::setPassword( const QString &password )
{
  d->mPassword = password;
}

void LdapServer::setTimeLimit( int timelimit )
{
  d->mTimeLimit = timelimit;
}

void LdapServer::setSizeLimit( int sizelimit )
{
  d->mSizeLimit = sizelimit;
}

void LdapServer::setPageSize( int pagesize )
{
  d->mPageSize = pagesize;
}

void LdapServer::setFilter( const QString &filter )
{
  d->mFilter = filter;
}

void LdapServer::setScope( LdapUrl::Scope scope )
{
  d->mScope = scope;
}

void LdapServer::setVersion( int version )
{
  d->mVersion = version;
}

void LdapServer::setSecurity( Security security )
{
  d->mSecurity = security;
}

void LdapServer::setAuth( Auth auth )
{
  d->mAuth = auth;
}

void LdapServer::setMech( const QString &mech )
{
  d->mMech = mech;
}

void LdapServer::setUrl( const LdapUrl &url )
{
  bool critical;

  d->mHost = url.host();
  int port = url.port();
  if ( port <= 0 ) {
    d->mPort = 389;
  } else {
    d->mPort = port;
  }
  d->mBaseDn = url.dn();
  d->mScope = url.scope();

  d->mFilter = url.filter();

  d->mSecurity = None;
  if ( url.protocol() == "ldaps" ) {
    d->mSecurity = SSL;
  } else if ( url.hasExtension("x-tls") ) {
    d->mSecurity = TLS;
  }
  kDebug(5322) << "security: " << d->mSecurity << endl;

  d->mMech = d->mUser = d->mBindDn = QString();
  if ( url.hasExtension("x-sasl") ) {
    d->mAuth = SASL;
    if ( url.hasExtension("x-mech") ) {
      d->mMech = url.extension( "x-mech", critical );
    }
    if ( url.hasExtension("x-realm") ) {
      d->mRealm = url.extension( "x-realm", critical );
    }
    if ( url.hasExtension("binddn") ) {
      d->mBindDn = url.extension( "bindname", critical );
    }
    d->mUser = url.user();
  } else if ( url.hasExtension( "bindname" ) ) {
    d->mAuth = Simple;
    d->mBindDn = url.extension( "bindname", critical );
  } else {
    QString user = url.user();
    if ( user.isEmpty() ) {
      d->mAuth = Anonymous;
    } else {
      d->mAuth = Simple;
      d->mBindDn = user;
    }
  }
  d->mPassword = url.password();
  if ( url.hasExtension("x-version") ) {
    d->mVersion = url.extension( "x-version", critical ).toInt();
  } else {
    d->mVersion = 3;
  }

  if ( url.hasExtension("x-timelimit") ) {
    d->mTimeLimit = url.extension( "x-timelimit", critical ).toInt();
  } else {
    d->mTimeLimit = 0;
  }

  if ( url.hasExtension("x-sizelimit") ) {
    d->mSizeLimit = url.extension( "x-sizelimit", critical ).toInt();
  } else {
    d->mSizeLimit = 0;
  }

  if ( url.hasExtension("x-pagesize") ) {
    d->mPageSize = url.extension( "x-pagesize", critical ).toInt();
  } else {
    d->mPageSize = 0;
  }
}

LdapUrl LdapServer::url() const
{
  LdapUrl url;
  url.setProtocol( d->mSecurity == SSL ? "ldaps" : "ldap" );
  url.setPort( d->mPort );
  url.setHost( d->mHost );
  url.setPassword( d->mPassword );
  url.setDn( d->mBaseDn );
  url.setFilter( d->mFilter );
  url.setScope( d->mScope );
  if ( d->mAuth == SASL ) {
    url.setUser( d->mUser );
    url.setExtension( "bindname", d->mBindDn, true );
    url.setExtension( "x-sasl", QString() );
    if ( !d->mMech.isEmpty() ) {
      url.setExtension( "x-mech", d->mMech );
    }
    if ( !d->mRealm.isEmpty() ) {
      url.setExtension( "x-realm", d->mRealm );
    }
  } else {
    url.setUser( d->mBindDn );
  }
  if ( d->mVersion == 2 ) {
    url.setExtension( "x-version", d->mVersion );
  }
  if ( d->mTimeLimit != 0 ) {
    url.setExtension( "x-timelimit", d->mTimeLimit );
  }
  if ( d->mSizeLimit != 0 ) {
    url.setExtension( "x-sizelimit", d->mSizeLimit );
  }
  if ( d->mPageSize != 0 ) {
    url.setExtension( "x-pagesize", d->mPageSize );
  }
  if ( d->mSecurity == TLS ) {
    url.setExtension( "x-tls", 1, true );
  }

  return url;
}
