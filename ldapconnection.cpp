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

#include <stdlib.h>
#include <klocale.h>
#include <kdebug.h>

#include <kldap_config.h> // SASL2_FOUND, LDAP_FOUND

#ifdef SASL2_FOUND
#include <sasl/sasl.h>
#endif

#ifdef LDAP_FOUND
#define LDAP_DEPRECATED 1 //for ldap_simple_bind_s
#include <lber.h>
#include <ldap.h>
#endif

using namespace KLDAP;

class LdapConnection::LdapConnectionPrivate
{
  public:
    LdapServer mServer;
    QString mConnectionError;

#ifdef LDAP_FOUND
    LDAP *mLDAP;
#else
    void *mLDAP;
#endif
};

LdapConnection::LdapConnection()
  : d( new LdapConnectionPrivate )
{
  d->mLDAP = 0;
}

LdapConnection::LdapConnection( const LdapUrl &url )
  : d( new LdapConnectionPrivate )
{
  d->mLDAP = 0;
  setUrl( url );
}

LdapConnection::LdapConnection( const LdapServer &server )
  : d( new LdapConnectionPrivate )
{
  d->mLDAP = 0;
  setServer( server );
}

LdapConnection::~LdapConnection()
{
  close();
  delete d;
}

void LdapConnection::setUrl( const LdapUrl &url )
{
  d->mServer.setUrl( url );
}

void LdapConnection::setServer( const LdapServer &server )
{
  d->mServer = server;
}

void *LdapConnection::handle() const
{
  return (void*) d->mLDAP;
}

QString LdapConnection::errorString( int code )
{
  //No translated error messages yet
#ifdef LDAP_FOUND
  return QString::fromUtf8( ldap_err2string( code ) );
  switch ( code ) {
    case LDAP_OPERATIONS_ERROR: return i18n("LDAP Operations error");
    //FIXME:
    /* add the LDAP error codes */
  }
#else
  return i18n("No LDAP Support...");
#endif
}

QString LdapConnection::connectionError() const
{
  return d->mConnectionError;
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

int LdapConnection::ldapErrorCode() const
{
  Q_ASSERT( d->mLDAP );
  int err;
  ldap_get_option( d->mLDAP, LDAP_OPT_ERROR_NUMBER, &err );
  return err;
}

QString LdapConnection::ldapErrorString() const
{
  Q_ASSERT( d->mLDAP );
  char *errmsg;
  ldap_get_option( d->mLDAP, LDAP_OPT_ERROR_STRING, &errmsg );
  QString msg = QString::fromLocal8Bit( errmsg );
  free( errmsg );
  return msg;
}

bool LdapConnection::setSizeLimit( int sizelimit )
{
  Q_ASSERT( d->mLDAP );
  kDebug(5322) << "sizelimit: " << sizelimit << endl;
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
  kDebug(5322) << "timelimit: " << timelimit << endl;
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
    int retval;
    if ( (retval = data->proc( data->creds, data->data )) ) {
      return retval;
    }
  }

  QString value;

  while ( interact->id != SASL_CB_LIST_END ) {
    value = QString();
    switch( interact->id ) {
      case SASL_CB_GETREALM:
        value = data->creds.realm;
        kDebug(5322) << "SASL_REALM=" << value << endl;
        break;
      case SASL_CB_AUTHNAME:
        value = data->creds.authname;
        kDebug(5322) << "SASL_AUTHNAME=" << value << endl;
        break;
      case SASL_CB_PASS:
        value = data->creds.password;
        kDebug(5322) << "SASL_PASSWD=[hidden]" << endl;
        break;
      case SASL_CB_USER:
        value = data->creds.authzid;
        kDebug(5322) << "SASL_AUTHZID=" << value << endl;
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

int LdapConnection::connect()
{
  int ret;
  QString url;
  if ( d->mLDAP ) {
    close();
  }

  int version = d->mServer.version();

  url = d->mServer.security() == LdapServer::SSL ? "ldaps" : "ldap";
  url += "://";
  url += d->mServer.host();
  url += ':';
  url += QString::number( d->mServer.port() );
  kDebug(5322) << "ldap url: " << url << endl;
  ret = ldap_initialize( &d->mLDAP, url.toLatin1() );
  if ( ret != LDAP_SUCCESS ) {
    d->mConnectionError = i18n("An error occurred during the connection initialization phase.");
    return ret;
  }

  kDebug(5322) << "setting version to: " << version << endl;
  if ( setOption( LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS ) {
    ret = ldapErrorCode();
      d->mConnectionError = i18n("Cannot set protocol version to %1.", version );
    close();
    return ret;
  }

  //FIXME: accessing to certificate handling would be good
  kDebug(5322) << "setting security to: " << d->mServer.security() << endl;
  if ( d->mServer.security() == LdapServer::TLS ) {
    kDebug(5322) << "start TLS" << endl;
    if ( ( ret = ldap_start_tls_s( d->mLDAP, NULL, NULL ) ) != LDAP_SUCCESS ) {
      close();
      d->mConnectionError = i18n("Cannot start TLS.");
      return ret;
    }
  }

  kDebug(5322) << "setting sizelimit to: " << d->mServer.sizeLimit() << endl;
  if ( d->mServer.sizeLimit() ) {
    if ( !setSizeLimit( d->mServer.sizeLimit() ) ) {
      ret = ldapErrorCode();
      close();
      d->mConnectionError = i18n("Cannot set size limit.");
      return ret;
    }
  }

  kDebug(5322) << "setting timelimit to: " << d->mServer.timeLimit() << endl;
  if ( d->mServer.timeLimit() ) {
    if ( !setTimeLimit( d->mServer.timeLimit() ) ) {
      ret = ldapErrorCode();
      close();
      d->mConnectionError = i18n("Cannot set time limit.");
      return ret;
    }
  }
  return 0;
}

int LdapConnection::bind( SASL_Callback_Proc *saslproc, void *data )
{
  int ret;

  if ( d->mServer.auth() == LdapServer::SASL ) {
#ifdef SASL2_FOUND
    QString mech = d->mServer.mech();
    if ( mech.isEmpty() ) {
      mech = "DIGEST-MD5";
    }

    SASL_Data sasldata;
    sasldata.proc = saslproc;
    sasldata.data = data;
    sasldata.creds.fields = 0;
    sasldata.creds.realm = d->mServer.realm();
    sasldata.creds.authname = d->mServer.user();
    sasldata.creds.authzid = d->mServer.bindDn();
    sasldata.creds.password = d->mServer.password();

    ret = ldap_sasl_interactive_bind_s( d->mLDAP, 0, mech.toLatin1(), 0, 0,
      LDAP_SASL_INTERACTIVE, &kldap_sasl_interact, &sasldata );
#else
    return -0xff;
#endif
  } else {
    QString bindname, pass;
    if ( d->mServer.auth() == LdapServer::Simple ) {
      bindname = d->mServer.bindDn();
      pass = d->mServer.password();
    }
    kDebug(5322) << "binding to server, bindname: " << bindname << " password: *****" << endl;
    ret = ldap_simple_bind_s( d->mLDAP, bindname.toUtf8(), pass.toUtf8() );
  }
  return ret;
}

void LdapConnection::close()
{
  if ( d->mLDAP ) {
    ldap_unbind_ext_s( d->mLDAP, 0, 0 );
  }
  d->mLDAP = 0;
  kDebug(5322) << "connection closed!" << endl;
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

int LdapConnection::ldapErrorCode() const
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

QString LdapConnection::ldapErrorString() const
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

int LdapConnection::connect( )
{
  d->mConnectionError = i18n("LDAP support not compiled in. Please recompile libkldap with the OpenLDAP (or compatible) client libraries, or complain to your distribution packagers.");
  kError() << "No LDAP support..." << endl;
  return -1;
}

int LdapConnection::bind( SASL_Callback_Proc *saslproc, void *data )
{
  kError() << "No LDAP support..." << endl;
  return -1;
}

void LdapConnection::close()
{
  kError() << "No LDAP support..." << endl;
}

#endif
