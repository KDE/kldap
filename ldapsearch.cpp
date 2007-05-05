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
#include "ldapdn.h"
#include "ldapdefs.h"

#include <QtCore/QEventLoop>
#include <QtCore/QTimer>

#include <kdebug.h>

using namespace KLDAP;

class LdapSearch::Private
{
  public:
    Private( LdapSearch *parent )
      : mParent( parent )
    {
    }

    void result();
    bool connect();
    void closeConnection();
    bool startSearch( const LdapDN &base, LdapUrl::Scope scope,
                      const QString &filter, const QStringList &attributes,
                      int pagesize );

    LdapSearch *mParent;
    LdapConnection *mConn;
    LdapOperation mOp;
    bool mOwnConnection, mAbandoned;
    int mId, mPageSize;
    LdapDN mBase;
    QString mFilter;
    QStringList mAttributes;
    LdapUrl::Scope mScope;

    QString mErrorString;
    int mError;
};

void LdapSearch::Private::result()
{
  if ( mAbandoned ) {
    mOp.abandon( mId );
    return;
  }
  int res = mOp.waitForResult( mId, -1 );
  if ( res == -1 || mConn->ldapErrorCode() != KLDAP_SUCCESS ) {
    mError = mConn->ldapErrorCode();
    mErrorString = mConn->ldapErrorString();
    emit mParent->result( mParent );
    return;
  }
  if ( res == LdapOperation::RES_SEARCH_RESULT ) {
    if ( mPageSize ) {
      QByteArray cookie;
      int estsize = -1;
      for ( int i = 0; i < mOp.controls().count(); ++i ) {
        estsize = mOp.controls()[i].parsePageControl( cookie );
        if ( estsize != -1 ) {
          break;
        }
      }
      kDebug(5322) << " estimated size: " << estsize << endl;
      if ( estsize != -1 && !cookie.isEmpty() ) {
        LdapControls ctrls, savedctrls;
        savedctrls = mOp.serverControls();
        ctrls = savedctrls;
        ctrls.append( LdapControl::createPageControl( mPageSize, cookie ) );
        mOp.setServerControls( ctrls );
        mId = mOp.search( mBase, mScope, mFilter, mAttributes );
        mOp.setServerControls( savedctrls );
        if ( mId == -1 ) {
          mError = mConn->ldapErrorCode();
          mErrorString = mConn->ldapErrorString();
          emit mParent->result( mParent );
          return;
        }
        QTimer::singleShot( 0, mParent, SLOT(result()) );
        return;
      }
    }
    emit mParent->result( mParent );
    return;
  }
  if ( res == LdapOperation::RES_SEARCH_ENTRY ) {
    emit mParent->data( mParent, mOp.object() );
  }
  QTimer::singleShot( 0, mParent, SLOT(result()) );
}

bool LdapSearch::Private::connect()
{
  int ret = mConn->connect();
  if ( ret != KLDAP_SUCCESS ) {
    mError = ret;
    mErrorString = mConn->connectionError();
    closeConnection();
    return false;
  }
  ret = mConn->bind();
  if ( ret != KLDAP_SUCCESS ) {
    mError = mConn->ldapErrorCode();
    mErrorString = mConn->ldapErrorString();
    closeConnection();
    return false;
  }
  return true;
}

void LdapSearch::Private::closeConnection()
{
  if ( mOwnConnection && mConn ) {
    delete mConn;
    mConn = 0;
  }
}

bool LdapSearch::Private::startSearch( const LdapDN &base, LdapUrl::Scope scope,
                                       const QString &filter,
                                       const QStringList &attributes, int pagesize )
{
  kDebug(5322) << "search: base=" << base.toString() << " scope=" << scope << " filter=" << filter
    << " attributes=" << attributes << " pagesize=" << pagesize  << endl;
  mAbandoned = false;
  mError = 0;
  mErrorString = QString();
  mOp.setConnection( *mConn );
  mPageSize = pagesize;
  mBase = base;
  mScope = scope;
  mFilter = filter;
  mAttributes = attributes;
  LdapControls savedctrls = mOp.serverControls();
  if ( pagesize ) {
    LdapControls ctrls = savedctrls;
    ctrls.append( LdapControl::createPageControl( pagesize ) );
    mOp.setServerControls( ctrls );
  }

  mId = mOp.search( base, scope, filter, attributes );
  if ( pagesize ) {
    mOp.setServerControls( savedctrls );
  }

  if ( mId == -1 ) {
    mError = mConn->ldapErrorCode();
    mErrorString = mConn->ldapErrorString();
    return false;
  }
  kDebug(5322) << "search::startSearch msg id=" << mId << endl;
  QTimer::singleShot( 0, mParent, SLOT(result()) ); //maybe do this with threads?
  return true;
}



LdapSearch::LdapSearch()
 : d( new Private( this ) )
{
  d->mOwnConnection = true;
  d->mConn = 0;
}

LdapSearch::LdapSearch( LdapConnection &connection )
 : d( new Private( this ) )
{
  d->mOwnConnection = false;
  d->mConn = &connection;
}

LdapSearch::~LdapSearch()
{
  d->closeConnection();
  delete d;
}

void LdapSearch::setConnection( LdapConnection &connection )
{
  d->closeConnection();
  d->mOwnConnection = false;
  d->mConn = &connection;
}

void LdapSearch::setClientControls( const LdapControls &ctrls )
{
  d->mOp.setClientControls( ctrls );
}

void LdapSearch::setServerControls( const LdapControls &ctrls )
{
  d->mOp.setServerControls( ctrls );
}

bool LdapSearch::search( const LdapServer &server,
                         const QStringList &attributes )
{
  if ( d->mOwnConnection ) {
    d->closeConnection();
    d->mConn = new LdapConnection( server );
    if ( !d->connect() ) {
      return false;
    }
  }
  return d->startSearch( server.baseDn(), server.scope(), server.filter(),
                         attributes, server.pageSize() );
}

bool LdapSearch::search( const LdapUrl &url )
{
  if ( d->mOwnConnection ) {
    d->closeConnection();
    d->mConn = new LdapConnection( url );
    if ( !d->connect() ) {
      return false;
    }
  }
  bool critical;
  int pagesize = url.extension( QLatin1String("x-pagesize"), critical ).toInt();
  return d->startSearch( url.dn(), url.scope(), url.filter(),
                         url.attributes(), pagesize );
}

bool LdapSearch::search( const LdapDN &base, LdapUrl::Scope scope,
                         const QString &filter, const QStringList &attributes,
                         int pagesize )
{
  Q_ASSERT( !d->mOwnConnection );
  return d->startSearch( base, scope, filter, attributes, pagesize );
}

void LdapSearch::abandon()
{
  d->mAbandoned = true;
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
