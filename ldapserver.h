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

#include <QString>

#include <kldap/ldapurl.h>
#include <kldap/kldap.h>

namespace KLDAP {

  /** This class holds various parameters about an LDAP server
   */
  class KLDAP_EXPORT LdapServer
  {
    public:
      LdapServer();
      LdapServer( const LdapUrl &url );
    
      virtual ~LdapServer();
    
      typedef enum Security{ None, TLS, SSL };
      typedef enum Auth{ Anonymous, Simple, SASL };

      void clear();
      
      QString host() const { return mHost; }
      int port() const { return mPort; }
      const QString &baseDn() const { return mBaseDn; }
      const QString &user() const { return mUser; }
      const QString &bindDn() const { return mBindDn; }
      const QString &realm() const { return mRealm; }
      const QString &password() const { return mPassword; }
      int timeLimit() const { return mTimeLimit; }
      int sizeLimit() const { return mSizeLimit; }
      int pageSize() const { return mPageSize; }
      int version() const { return mVersion; }
      Security security() const { return mSecurity; }
      Auth auth() const { return mAuth; }
      const QString &mech() const { return mMech; }

      void setHost( const QString &host ) { mHost = host; }
      void setPort( int port ) { mPort = port; }
      void setBaseDn( const QString &baseDn ) {  mBaseDn = baseDn; }
      void setUser( const QString &user ) { mUser = user; }
      void setBindDn( const QString &bindDn ) {  mBindDn = bindDn; }
      void setRealm( const QString &realm ) {  mRealm = realm; }
      void setPassword( const QString &password ) {  mPassword = password; }
      void setTimeLimit( int timelimit ) { mTimeLimit = timelimit; }
      void setSizeLimit( int sizelimit ) { mSizeLimit = sizelimit; }
      void setPageSize( int pagesize ) { mPageSize = pagesize; }
      void setVersion( int version ) { mVersion = version; }
      void setSecurity( Security security ) { mSecurity = security; }
      void setAuth( Auth auth ) { mAuth = auth; }
      void setMech( const QString &mech ) { mMech = mech; }
    
      LdapUrl url() const;
      void setUrl( const LdapUrl &url );

    private:
      QString mHost;
      int mPort;
      QString mBaseDn;
      QString mUser;
      QString mBindDn;
      QString mRealm;
      QString mPassword;
      QString mMech;
      int mTimeLimit, mSizeLimit, mVersion, mPageSize;
      Security mSecurity;
      Auth mAuth;
    
      class LdapServerPrivate;
      LdapServerPrivate *d;
  };

}
#endif
