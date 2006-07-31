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

LdapServer::LdapServer()
{
  clear();
}

LdapServer::LdapServer( const LdapUrl &url )
{
  clear();
  setUrl( url );
}

LdapServer::~LdapServer()
{
}

void LdapServer::clear()
{
  mPort = 389;
  mHost = mUser = mBindDn = mMech = mPassword = QString();
  mSecurity = None;
  mAuth = Anonymous;
  mVersion = 3;
  mSizeLimit = mTimeLimit = mPageSize = 0;
}

void LdapServer::setUrl( const LdapUrl &url )
{
  bool critical;
  
  mHost = url.host();
  int port = url.port();
  if ( port <= 0 ) mPort = 389; else mPort = port;
  mBaseDn = url.dn();
  
  mSecurity = None;
  if ( url.protocol() == "ldaps" ) 
    mSecurity = SSL; 
  else if ( url.hasExtension("x-tls") )
    mSecurity = TLS;
  kDebug() << "security: " << mSecurity << endl;

  mMech = mUser = mBindDn = QString();
  if ( url.hasExtension("x-sasl") ) {
    mAuth = SASL;
    if ( url.hasExtension("x-mech") )
      mMech = url.extension( "x-mech", critical );
    if ( url.hasExtension("x-realm") ) 
      mRealm = url.extension( "x-realm", critical );
    if ( url.hasExtension("binddn") ) 
      mBindDn = url.extension( "binddn", critical );
    mUser = url.user();
  } else if ( url.hasExtension( "binddn" ) ) {
    mAuth = Simple;
    mBindDn = url.extension( "binddn", critical );
  } else {
    QString user = url.user();
    if ( user.isEmpty() ) {
      mAuth = Anonymous;
    } else {
      mAuth = Simple;
      mBindDn = user;
    }
  }
  mPassword = url.password();
  if ( url.hasExtension("x-version") ) 
    mVersion = url.extension( "x-version", critical ).toInt();
  else 
    mVersion = 3;

  if ( url.hasExtension("x-timelimit") ) 
    mTimeLimit = url.extension( "x-timelimit", critical ).toInt();
  else 
    mTimeLimit = 0;

  if ( url.hasExtension("x-sizelimit") ) 
    mSizeLimit = url.extension( "x-sizelimit", critical ).toInt();
  else 
    mSizeLimit = 0;

  if ( url.hasExtension("x-pagesize") ) 
    mPageSize = url.extension( "x-pagesize", critical ).toInt();
  else 
    mPageSize = 0;
}

LdapUrl LdapServer::url() const
{
  LdapUrl url;
  url.setProtocol( mSecurity == SSL ? "ldaps" : "ldap" );
  url.setPort( mPort );
  url.setHost( mHost );
  url.setPassword( mPassword );
  url.setDn( mBaseDn );
  if ( mAuth == SASL ) {
    url.setUser( mUser );
    url.setExtension( "binddn", mBindDn, true );
    url.setExtension( "x-sasl", QString() );
    if ( !mMech.isEmpty() ) url.setExtension( "x-mech", mMech );
    if ( !mRealm.isEmpty() ) url.setExtension( "x-realm", mRealm );
  } else {
    url.setUser( mBindDn );
  }
  if ( mVersion == 2 ) url.setExtension( "x-version", mVersion );
  if ( mTimeLimit != 0 ) url.setExtension( "x-timelimit", mTimeLimit );
  if ( mSizeLimit != 0 ) url.setExtension( "x-sizelimit", mSizeLimit );
  if ( mPageSize != 0 ) url.setExtension( "x-pagesize", mPageSize );
  if ( mSecurity == TLS ) url.setExtension( "x-tls", 1, true );
  
  return url;
}
