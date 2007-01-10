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

#include <QtCore/QEventLoop>
#include <QtCore/QTimer>

#include <kdebug.h>

using namespace KLDAP;

class LdapSearch::LdapSearchPrivate {
  public:
    LdapConnection *mConn;
    LdapOperation mOp;
    bool mOwnConnection, mAbandoned;
    int mId, mPageSize;
    QString mBase, mFilter;
    QStringList mAttributes;
    LdapUrl::Scope mScope;

    QString mErrorString;
    int mError;
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

void LdapSearch::setConnection( LdapConnection &connection )
{
  closeConnection();
  d->mOwnConnection = false;
  d->mConn = &connection;
}

void LdapSearch::closeConnection()
{
  if ( d->mOwnConnection && d->mConn ) {
    delete d->mConn;
    d->mConn = 0;
  }
}

void LdapSearch::setClientControls( const LdapControls &ctrls )
{
  d->mOp.setClientControls( ctrls );
}

void LdapSearch::setServerControls( const LdapControls &ctrls )
{
  d->mOp.setServerControls( ctrls );
}

bool LdapSearch::connect()
{
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
  return true;
}

bool LdapSearch::search( const LdapServer &server,
                         const QStringList &attributes )
{
  if ( d->mOwnConnection ) {
    closeConnection();
    d->mConn = new LdapConnection( server );
    if ( !connect() ) {
      return false;
    }
  }
  return startSearch( server.baseDn(), server.scope(), server.filter(),
                      attributes, server.pageSize() );
}

bool LdapSearch::search( const LdapUrl &url )
{
  if ( d->mOwnConnection ) {
    closeConnection();
    d->mConn = new LdapConnection( url );
    if ( !connect() ) {
      return false;
    }
  }
  bool critical;
  int pagesize = url.extension( QLatin1String("x-pagesize"), critical ).toInt();
  return startSearch( url.dn(), url.scope(), url.filter(),
                      url.attributes(), pagesize );
}

bool LdapSearch::search( const QString &base, LdapUrl::Scope scope,
                         const QString &filter, const QStringList &attributes,
                         int pagesize )
{
  Q_ASSERT( !d->mOwnConnection );
  return startSearch( base, scope, filter, attributes, pagesize );
}

bool LdapSearch::startSearch( const QString &base, LdapUrl::Scope scope,
                              const QString &filter,
                              const QStringList &attributes, int pagesize )
{
  kDebug() << "search: base=" << base << " scope=" << scope << " filter=" << filter
    << " attributes=" << attributes << " pagesize=" << pagesize  << endl;
  d->mAbandoned = false;
  d->mError = 0;
  d->mErrorString = QString();
  d->mOp.setConnection( *d->mConn );
  d->mPageSize = pagesize;
  d->mBase = base;
  d->mScope = scope;
  d->mFilter = filter;
  d->mAttributes = attributes;
  LdapControls savedctrls = d->mOp.serverControls();
  if ( pagesize ) {
    LdapControls ctrls = savedctrls;
    ctrls.append( LdapControl::createPageControl( pagesize ) );
    d->mOp.setServerControls( ctrls );
  }

  d->mId = d->mOp.search( base, scope, filter, attributes );
  if ( pagesize ) {
    d->mOp.setServerControls( savedctrls );
  }

  if ( d->mId == -1 ) {
    return false;
  }
  kDebug() << "search::startSearch msg id=" << d->mId << endl;
  QTimer::singleShot( 0, this, SLOT(result()) ); //maybe do this with threads?
  return true;
}

void LdapSearch::abandon()
{
  d->mAbandoned = true;
}

void LdapSearch::result()
{
  if ( d->mAbandoned ) {
    d->mOp.abandon( d->mId );
    return;
  }
  int res = d->mOp.result( d->mId );
  if ( res == -1 || d->mConn->ldapErrorCode() != KLDAP_SUCCESS ) {
    d->mError = d->mConn->ldapErrorCode();
    d->mErrorString = d->mConn->ldapErrorString();
    emit result( this );
    return;
  }
  if ( res == LdapOperation::RES_SEARCH_RESULT ) {
    if ( d->mPageSize ) {
      QByteArray cookie;
      int estsize = -1;
      for ( int i = 0; i < d->mOp.controls().count(); ++i ) {
        estsize = d->mOp.controls()[i].parsePageControl( cookie );
        if ( estsize != -1 ) {
          break;
        }
      }
      kDebug() << " estimated size: " << estsize << endl;
      if ( estsize != -1 && !cookie.isEmpty() ) {
        LdapControls ctrls, savedctrls;
        savedctrls = d->mOp.serverControls();
        ctrls = savedctrls;
        ctrls.append( LdapControl::createPageControl( d->mPageSize, cookie ) );
        d->mOp.setServerControls( ctrls );
        d->mId = d->mOp.search( d->mBase, d->mScope, d->mFilter, d->mAttributes );
        d->mOp.setServerControls( savedctrls );
        if ( d->mId == -1 ) {
          d->mError = d->mConn->ldapErrorCode();
          d->mErrorString = d->mConn->ldapErrorString();
          emit result( this );
          return;
        }
        QTimer::singleShot( 0, this, SLOT(result()) );
        return;
      }
    }
    emit result( this );
    return;
  }
  if ( res == LdapOperation::RES_SEARCH_ENTRY ) {
    emit data( this, d->mOp.object() );
  }
  QTimer::singleShot( 0, this, SLOT(result()) );
}

int LdapSearch::error() const
{
  return d->mError;
}

QString LdapSearch::errorString() const
{
  return d->mErrorString;
}

#include "ldapsearch.moc"
