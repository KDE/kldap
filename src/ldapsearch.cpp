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

#include <qdebug.h>
#include <KLocalizedString>
using namespace KLDAP;

//blocking the GUI for xxx milliseconds
#define LDAPSEARCH_BLOCKING_TIMEOUT 10

class LdapSearch::Private
{
public:
    Private(LdapSearch *parent)
        : mParent(parent)
    {
    }

    void result();
    bool connect();
    void closeConnection();
    bool startSearch(const LdapDN &base, LdapUrl::Scope scope,
                     const QString &filter, const QStringList &attributes,
                     int pagesize, int count);

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
    int mCount, mMaxCount;
    bool mFinished;
};

void LdapSearch::Private::result()
{
    if (mAbandoned) {
        mOp.abandon(mId);
        return;
    }
    int res = mOp.waitForResult(mId, LDAPSEARCH_BLOCKING_TIMEOUT);

    qDebug() << "LDAP result:" << res;

    if (res != 0 &&
            (res == -1 ||
             (mConn->ldapErrorCode() != KLDAP_SUCCESS &&
              mConn->ldapErrorCode() != KLDAP_SASL_BIND_IN_PROGRESS))) {
        //error happened, but no timeout
        mError = mConn->ldapErrorCode();
        mErrorString = mConn->ldapErrorString();
        emit mParent->result(mParent);
        return;
    }

    //binding
    if (res == LdapOperation::RES_BIND) {

        QByteArray servercc;
        servercc = mOp.serverCred();

        qDebug() << "LdapSearch RES_BIND";
        if (mConn->ldapErrorCode() == KLDAP_SUCCESS) {   //bind succeeded
            qDebug() << "bind succeeded";
            LdapControls savedctrls = mOp.serverControls();
            if (mPageSize) {
                LdapControls ctrls = savedctrls;
                LdapControl::insert(ctrls, LdapControl::createPageControl(mPageSize));
                mOp.setServerControls(ctrls);
            }

            mId = mOp.search(mBase, mScope, mFilter, mAttributes);
            mOp.setServerControls(savedctrls);
        } else { //next bind step
            qDebug() << "bind next step";
            mId = mOp.bind(servercc);
        }
        if (mId < 0) {
            if (mId == KLDAP_SASL_ERROR) {
                mError = mId;
                mErrorString = mConn->saslErrorString();
            } else {
                mError = mConn->ldapErrorCode();
                mErrorString = mConn->ldapErrorString();
            }
            emit mParent->result(mParent);
            return;
        }
        QTimer::singleShot(0, mParent, SLOT(result()));
        return;
    }

    //End of entries
    if (res == LdapOperation::RES_SEARCH_RESULT) {
        if (mPageSize) {
            QByteArray cookie;
            int estsize = -1;
            const int numberOfControls(mOp.controls().count());
            for (int i = 0; i < numberOfControls; ++i) {
                estsize = mOp.controls()[i].parsePageControl(cookie);
                if (estsize != -1) {
                    break;
                }
            }
            qDebug() << " estimated size:" << estsize;
            if (estsize != -1 && !cookie.isEmpty()) {
                LdapControls ctrls, savedctrls;
                savedctrls = mOp.serverControls();
                ctrls = savedctrls;
                LdapControl::insert(ctrls, LdapControl::createPageControl(mPageSize, cookie));
                mOp.setServerControls(ctrls);
                mId = mOp.search(mBase, mScope, mFilter, mAttributes);
                mOp.setServerControls(savedctrls);
                if (mId == -1) {
                    mError = mConn->ldapErrorCode();
                    mErrorString = mConn->ldapErrorString();
                    emit mParent->result(mParent);
                    return;
                }
                //continue with the next page
                QTimer::singleShot(0, mParent, SLOT(result()));
                return;
            }
        }
        mFinished = true;
        emit mParent->result(mParent);
        return;
    }

    //Found an entry
    if (res == LdapOperation::RES_SEARCH_ENTRY) {
        emit mParent->data(mParent, mOp.object());
        mCount++;
    }

    //If not reached the requested entries, continue
    if (mMaxCount <= 0 || mCount < mMaxCount) {
        QTimer::singleShot(0, mParent, SLOT(result()));
    }
    //If reached the requested entries, indicate it
    if (mMaxCount > 0 && mCount == mMaxCount) {
        qDebug() << mCount << " entries reached";
        emit mParent->result(mParent);
    }
}

bool LdapSearch::Private::connect()
{
    int ret = mConn->connect();
    if (ret != KLDAP_SUCCESS) {
        mError = ret;
        mErrorString = mConn->connectionError();
        closeConnection();
        return false;
    }
    return true;
}

void LdapSearch::Private::closeConnection()
{
    if (mOwnConnection && mConn) {
        delete mConn;
        mConn = 0;
    }
}

//This starts the real job
bool LdapSearch::Private::startSearch(const LdapDN &base, LdapUrl::Scope scope,
                                      const QString &filter,
                                      const QStringList &attributes, int pagesize, int count)
{
    qDebug() << "search: base=" << base.toString() << "scope=" << (int)scope
             << "filter=" << filter << "attributes=" << attributes
             << "pagesize=" << pagesize;
    mAbandoned = false;
    mError = 0;
    mErrorString.clear();
    mOp.setConnection(*mConn);
    mPageSize = pagesize;
    mBase = base;
    mScope = scope;
    mFilter = filter;
    mAttributes = attributes;
    mMaxCount = count;
    mCount = 0;
    mFinished = false;

    LdapControls savedctrls = mOp.serverControls();
    if (pagesize) {
        LdapControls ctrls = savedctrls;
        mConn->setOption(0x0008, NULL);   // Disable referals or paging won't work
        LdapControl::insert(ctrls, LdapControl::createPageControl(pagesize));
        mOp.setServerControls(ctrls);
    }

    mId = mOp.bind();
    if (mId < 0) {
        if (mId == KLDAP_SASL_ERROR) {
            mError = mId;
            mErrorString = mConn->saslErrorString();
        } else {
            mError = mConn->ldapErrorCode();
            mErrorString = mConn->ldapErrorString();
            if (mError == -1 && mErrorString.isEmpty()) {
                mErrorString = i18n("Cannot access to server. Please reconfigure it.");
            }
        }
        return false;
    }
    qDebug() << "startSearch msg id=" << mId;

    //maybe do this with threads?- need thread-safe client libs!!!
    QTimer::singleShot(0, mParent, SLOT(result()));

    return true;
}

///////////////////////////////////////////////

LdapSearch::LdapSearch()
    : d(new Private(this))
{
    d->mOwnConnection = true;
    d->mConn = 0;
}

LdapSearch::LdapSearch(LdapConnection &connection)
    : d(new Private(this))
{
    d->mOwnConnection = false;
    d->mConn = &connection;
}

LdapSearch::~LdapSearch()
{
    d->closeConnection();
    delete d;
}

void LdapSearch::setConnection(LdapConnection &connection)
{
    d->closeConnection();
    d->mOwnConnection = false;
    d->mConn = &connection;
}

void LdapSearch::setClientControls(const LdapControls &ctrls)
{
    d->mOp.setClientControls(ctrls);
}

void LdapSearch::setServerControls(const LdapControls &ctrls)
{
    d->mOp.setServerControls(ctrls);
}

bool LdapSearch::search(const LdapServer &server,
                        const QStringList &attributes, int count)
{
    if (d->mOwnConnection) {
        d->closeConnection();
        d->mConn = new LdapConnection(server);
        if (!d->connect()) {
            return false;
        }
    }
    return d->startSearch(server.baseDn(), server.scope(), server.filter(),
                          attributes, server.pageSize(), count);
}

bool LdapSearch::search(const LdapUrl &url, int count)
{
    if (d->mOwnConnection) {
        d->closeConnection();
        d->mConn = new LdapConnection(url);
        if (!d->connect()) {
            return false;
        }
    }
    bool critical = true;
    int pagesize = url.extension(QLatin1String("x-pagesize"), critical).toInt();
    return d->startSearch(url.dn(), url.scope(), url.filter(),
                          url.attributes(), pagesize, count);
}

bool LdapSearch::search(const LdapDN &base, LdapUrl::Scope scope,
                        const QString &filter, const QStringList &attributes,
                        int pagesize, int count)
{
    Q_ASSERT(!d->mOwnConnection);
    return d->startSearch(base, scope, filter, attributes, pagesize, count);
}

void LdapSearch::continueSearch()
{
    Q_ASSERT(!d->mFinished);
    d->mCount = 0;
    QTimer::singleShot(0, this, SLOT(result()));
}

bool LdapSearch::isFinished()
{
    return d->mFinished;
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

#include "moc_ldapsearch.cpp"
