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

#include "ldapsearch.h"
#include "ldapdefs.h"

#include "QtCore/QEventLoop"
#include "QtCore/QTimer"

#include <kdebug.h>

using namespace KLDAP;

class LdapSearch::LdapSearchPrivate {
  public:
    LdapConnection *mConn;
    LdapOperation mOp;
    bool mOwnConnection;
    int mId;
};

LdapSearch::LdapSearch()
 : d( new LdapSearchPrivate )
{
  d->mOwnConnection = true;
  d->mConn = 0;
}

LdapSearch::LdapSearch( LdapConnection &connection ) 
 : d( new LdapSearchPrivate )
{
  d->mOwnConnection = false;
  d->mConn = &connection;
}

LdapSearch::~LdapSearch()
{
  closeConnection();
  delete d;
}

void LdapSearch::closeConnection()
{
  if ( d->mOwnConnection && d->mConn ) {
    delete d->mConn;
    d->mConn = 0;
  }
}

bool LdapSearch::search( const LdapServer &server, LdapUrl::Scope scope,
  const QStringList& attributes )
{
  closeConnection();
  d->mConn = new LdapConnection( server );
  int ret = d->mConn->connect();
  if ( ret != KLDAP_SUCCESS ) {
    closeConnection();
    return false;
  }
  ret = d->mConn->bind();
  if ( ret != KLDAP_SUCCESS ) {
    closeConnection();
    return false;
  }
  return startSearch( server.baseDn(), scope, server.filter(), attributes, server.pageSize() );
}

bool LdapSearch::search( const LdapUrl &url )
{
  closeConnection();
  d->mConn = new LdapConnection( url );
  int ret = d->mConn->connect();
  kDebug() << "search::connect() " << ret << endl;
  if ( ret != KLDAP_SUCCESS ) {
    closeConnection();
    return false;
  }
  ret = d->mConn->bind();
  kDebug() << "search::bind() " << ret << endl;
  if ( ret != KLDAP_SUCCESS ) {
    closeConnection();
    return false;
  }
  bool critical;
  int pagesize = url.extension( QLatin1String("x-pagesize"), critical ).toInt();
  return startSearch( url.dn(), url.scope(), url.filter(), url.attributes(), pagesize );
}

bool LdapSearch::search( const QString &base, LdapUrl::Scope scope,
  const QString &filter, const QStringList& attributes, int pagesize )
{
  Q_ASSERT( !d->mOwnConnection );
  return startSearch( base, scope, filter, attributes, pagesize );
}

bool LdapSearch::startSearch( const QString &base, LdapUrl::Scope scope,
  const QString &filter, const QStringList& attributes, int pagesize )
{
  kDebug() << "search: base=" << base << " scope=" << scope << " filter=" << filter 
    << " attributes=" << attributes << " pagesize=" << pagesize  << endl;
  d->mOp.setConnection( *d->mConn );
  d->mId = d->mOp.search( base, scope, filter, attributes );
  if ( d->mId == -1 ) {
    return false;
  }
  kDebug() << "search::startSearch msg id=" << d->mId << endl;
  QTimer::singleShot( 0, this, SLOT(result()) ); //maybe do this with threads?
  return true;  
}              

void LdapSearch::result()
{
  int res = d->mOp.result( d->mId );
  if ( res == -1 || d->mConn->ldapErrorCode() != KLDAP_SUCCESS ) {
    emit error( d->mConn->ldapErrorCode(), d->mConn->ldapErrorString() );
    emit done();
    return;
  }
  if ( res == LdapOperation::RES_SEARCH_RESULT ) {
    emit done();
    return;
  }
  if ( res == LdapOperation::RES_SEARCH_ENTRY ) {
    emit data( d->mOp.object() );
  }
  QTimer::singleShot( 0, this, SLOT(result()) );
}

#include "ldapsearch.moc"
