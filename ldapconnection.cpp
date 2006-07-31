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

#include "ldapconnection.h"

#include <klocale.h>
#include <kdebug.h>

#include <kldap_config.h>

#ifdef SASL2_FOUND
#include <sasl/sasl.h>
#endif

#ifdef LDAP_FOUND
#define LDAP_DEPRECATED 1 //for ldap_simple_bind_s
#include <ldap.h>
#include <lber.h>
#endif

using namespace KLDAP;


class LdapConnection::LdapConnectionPrivate 
{
  public:
#ifdef LDAP_FOUND
    LDAP *mLDAP;
#else
    void *mLDAP;
#endif
};

LdapConnection::LdapConnection()
{
  d = new LdapConnection::LdapConnectionPrivate();
  d->mLDAP = 0;
}

LdapConnection::LdapConnection( const LdapUrl &url )
{
  d = new LdapConnection::LdapConnectionPrivate();
  d->mLDAP = 0;
  setUrl( url );
}

LdapConnection::LdapConnection( const LdapServer &server )
{
  d = new LdapConnection::LdapConnectionPrivate();
  d->mLDAP = 0;
  setServer( server );
}
                  
LdapConnection::~LdapConnection()
{
  delete d;
  close();
}

void LdapConnection::setUrl( const LdapUrl &url )
{
  mServer.setUrl( url );
}

void LdapConnection::setServer( const LdapServer &server )
{
  mServer = server;
}

void *LdapConnection::handle() const
{
  return (void*) d->mLDAP;
}

QString LdapConnection::ldapError( int code )
{
  return i18n("No translated LDAP messages yet...");
#ifdef LDAP_FOUND
  switch ( code ) {
    case LDAP_OPERATIONS_ERROR: return i18n("LDAP Operations error");
    //FIXME:
    /* add the LDAP error codes */
  }
#else
  return i18n("No LDAP Support...");
#endif
}

#ifdef LDAP_FOUND
int LdapConnection::getOption( int option, void *value ) const
{
  Q_ASSERT( d->mLDAP );
  return ldap_get_option( d->mLDAP, option, value );
}

int LdapConnection::setOption( int option, void *value )
{
  Q_ASSERT( d->mLDAP );
  return ldap_set_option( d->mLDAP, option, value );
}

int LdapConnection::ldapErrorCode()
{
  Q_ASSERT( d->mLDAP );
  int err;
  ldap_get_option( d->mLDAP, LDAP_OPT_ERROR_NUMBER, &err );
  return err;
}

QString LdapConnection::ldapErrorString()
{
  Q_ASSERT( d->mLDAP );
  char *errmsg;
  ldap_get_option( d->mLDAP, LDAP_OPT_ERROR_STRING, &errmsg );
  return QString::fromLocal8Bit( errmsg );
}

bool LdapConnection::setSizeLimit( int sizelimit )
{
  Q_ASSERT( d->mLDAP );
  kDebug() << "sizelimit: " << sizelimit << endl;
  if ( setOption( LDAP_OPT_SIZELIMIT, &sizelimit ) != LDAP_OPT_SUCCESS ) {
    return false;
  }
  return true;
}

int LdapConnection::sizeLimit() const
{
  Q_ASSERT( d->mLDAP );
  int sizelimit;
  if ( getOption( LDAP_OPT_SIZELIMIT, &sizelimit ) != LDAP_OPT_SUCCESS ) {
    return -1;
  }
  return sizelimit;
}

bool LdapConnection::setTimeLimit( int timelimit )
{
  Q_ASSERT( d->mLDAP );
  kDebug() << "timelimit: " << timelimit << endl;
  if ( setOption( LDAP_OPT_TIMELIMIT, &timelimit ) != LDAP_OPT_SUCCESS ) {
    return false;
  }
  return true;
}

int LdapConnection::timeLimit() const
{
  Q_ASSERT( d->mLDAP );
  int timelimit;
  if ( getOption( LDAP_OPT_TIMELIMIT, &timelimit ) != LDAP_OPT_SUCCESS ) {
    return -1;
  }
  return timelimit;
}

static int kldap_sasl_interact( LDAP *, unsigned, void *defaults, void *in )
{
#ifdef SASL2_FOUND
  LdapConnection::SASL_Data *data = (LdapConnection::SASL_Data*) defaults;
  sasl_interact_t *interact = ( sasl_interact_t * ) in;

  if ( data->proc ) {
    for ( ; interact->id != SASL_CB_LIST_END; interact++ ) {
      switch ( interact->id ) {
        case SASL_CB_GETREALM:
          data->creds.fields |= LdapConnection::SASL_Realm;
          break;
        case SASL_CB_AUTHNAME:
          data->creds.fields |= LdapConnection::SASL_Authname;
          break;
        case SASL_CB_PASS:
          data->creds.fields |= LdapConnection::SASL_Password;
          break;
        case SASL_CB_USER:
          data->creds.fields |= LdapConnection::SASL_Authzid;
          break;
      }
    }
    if ( data->proc( data->creds, data->data ) ) return LDAP_OTHER;
  }

  QString value;
  
  while( interact->id != SASL_CB_LIST_END ) {
    value = QString();
    switch( interact->id ) {
      case SASL_CB_GETREALM:
        value = data->creds.realm;
        kDebug() << "SASL_REALM=" << value << endl;
        break;
      case SASL_CB_AUTHNAME:
        value = data->creds.authname;
        kDebug() << "SASL_AUTHNAME=" << value << endl;
        break;
      case SASL_CB_PASS:
        value = data->creds.password;
        kDebug() << "SASL_PASSWD=[hidden]" << endl;
        break;
      case SASL_CB_USER:
        value = data->creds.authzid;
        kDebug() << "SASL_AUTHZID=" << value << endl;
        break;
    }
  }
  if ( value.isEmpty() ) {
    interact->result = NULL;
    interact->len = 0;
  } else {
    interact->result = strdup( value.toUtf8() );
    interact->len = strlen( (const char *) interact->result );
  }
  interact++;
#endif
  return LDAP_SUCCESS;
}

int LdapConnection::connect( SASL_Callback_Proc *saslproc, void *data )
{
  int ret;
  QString url;
  if ( d->mLDAP ) close();
  
  int version = mServer.version();

  url = mServer.security() == LdapServer::SSL ? "ldaps" : "ldap";
  url += "://";
  url += mServer.host();
  url += ":";
  url += QString::number( mServer.port() );
  kDebug() << "ldap url: " << url << endl;
  ret = ldap_initialize( &d->mLDAP, url.toLatin1() );
  if ( ret != LDAP_SUCCESS ) {
    mError = i18n("An error occured during the connection initialization phase");
    return ret;
  }

  kDebug() << "setting version to: " << version << endl;
  if ( (setOption( LDAP_OPT_PROTOCOL_VERSION, &version )) != LDAP_OPT_SUCCESS ) {
    ret = ldapErrorCode();
      mError = i18n("Cannot set protocol version to %1.").arg(version);
    close();
    return ret;
  }

  //FIXME: accessing to certificate handling would be good
  kDebug() << "setting security to: " << mServer.security() << endl;
  if ( mServer.security() == LdapServer::TLS ) {
    kDebug() << "start TLS" << endl;
    if ( ( ret = ldap_start_tls_s( d->mLDAP, NULL, NULL ) ) != LDAP_SUCCESS ) {
      close();
      mError = i18n("Cannot start TLS.");
      return ret;
    }
  }
  
  kDebug() << "setting sizelimit to: " << mServer.sizeLimit() << endl;
  if ( mServer.sizeLimit() ) {
    if ( !setSizeLimit( mServer.sizeLimit() ) ) {
      ret = ldapErrorCode();
      close();
      mError = i18n("Cannot set size limit.");
      return ret;
    }
  }

  kDebug() << "setting timelimit to: " << mServer.timeLimit() << endl;
  if ( mServer.timeLimit() ) {
    if ( !setTimeLimit( mServer.timeLimit() ) ) {
      ret = ldapErrorCode();
      close();
      mError = i18n("Cannot set time limit.");
      return ret;
    }
  }

  if ( mServer.auth() == LdapServer::SASL ) {
#ifdef SASL2_FOUND
    QString mech = mServer.mech();
    if ( mech.isEmpty() ) mech = "DIGEST-MD5";

    SASL_Data sasldata;
    sasldata.proc = saslproc;
    sasldata.data = data;
    sasldata.creds.fields = 0;
    sasldata.creds.realm = mServer.realm();
    sasldata.creds.authname = mServer.user();
    sasldata.creds.authzid = mServer.bindDn();
    sasldata.creds.password = mServer.password();
    
    ret = ldap_sasl_interactive_bind_s( d->mLDAP, 0, mech.toLatin1(), 0, 0,
      LDAP_SASL_INTERACTIVE, &kldap_sasl_interact, &sasldata );
#else
    mError = i18n("No SASL support.");
    close();
    return -1;
#endif
  } else {
    QString bindname, pass;
    if ( mServer.auth() == LdapServer::Simple ) {
      bindname = mServer.bindDn();
      pass = mServer.password();
    }
    kDebug() << "binding to server, bindname: " << bindname << " password: *****" << endl;
    ret = ldap_simple_bind_s( d->mLDAP, bindname.toUtf8(), pass.toUtf8() );
  }
  if ( ret != LDAP_SUCCESS ) {
    mError = i18n("Cannot bind to LDAP server");
    close();
  }
  return ret;
}

void LdapConnection::close()
{
  if ( d->mLDAP ) ldap_unbind_ext_s( d->mLDAP, 0, 0 );
  d->mLDAP = 0;
  kDebug() << "connection closed!" << endl;
}
#else //LDAP_FOUND

int LdapConnection::getOption( int option, void *value ) const
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

int LdapConnection::setOption( int option, void *value )
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

int LdapConnection::ldapErrorCode()
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

QString LdapConnection::ldapErrorString()
{
  kError() << "No LDAP support..." << endl;
  return QString();
}

bool LdapConnection::setSizeLimit( int sizelimit )
{
  kError() << "No LDAP support..." << endl;
  return false;
}

int LdapConnection::sizeLimit() const
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

bool LdapConnection::setTimeLimit( int timelimit )
{
  kError() << "No LDAP support..." << endl;
  return false;
}

int LdapConnection::timeLimit() const
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

int LdapConnection::connect( SASL_Callback_Proc *saslproc, void *data )
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

void LdapConnection::close()
{
  kError() << "No LDAP support..." << endl;
}

#endif
