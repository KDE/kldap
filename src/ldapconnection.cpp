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
#include "ldapdefs.h"
#include "kldap_config.h" // SASL2_FOUND, LDAP_FOUND

#include <stdlib.h>
#include <klocalizedstring.h>
#include <qdebug.h>

#ifdef SASL2_FOUND
#include <sasl/sasl.h>
static sasl_callback_t callbacks[] = {
    { SASL_CB_ECHOPROMPT, NULL, NULL },
    { SASL_CB_NOECHOPROMPT, NULL, NULL },
    { SASL_CB_GETREALM, NULL, NULL },
    { SASL_CB_USER, NULL, NULL },
    { SASL_CB_AUTHNAME, NULL, NULL },
    { SASL_CB_PASS, NULL, NULL },
    { SASL_CB_CANON_USER, NULL, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static bool ldapoperation_sasl_initialized = false;
#endif

#ifdef LDAP_FOUND
# ifndef HAVE_WINLDAP_H
#  include <lber.h>
#  include <ldap.h>
#else
# include <w32-ldap-help.h>
#endif // HAVE_WINLDAP_H

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS 0
#endif

#endif

using namespace KLDAP;

class LdapConnection::LdapConnectionPrivate
{
public:
    LdapConnectionPrivate();
    LdapServer mServer;
    QString mConnectionError;

#ifdef LDAP_FOUND
    LDAP *mLDAP;
#else
    void *mLDAP;
#endif
#ifdef SASL2_FOUND
    sasl_conn_t *mSASLconn;
#else
    void *mSASLconn;
#endif

};

LdapConnection::LdapConnectionPrivate::LdapConnectionPrivate()
{
    mSASLconn = 0;
#ifdef SASL2_FOUND
    if (!ldapoperation_sasl_initialized) {
        sasl_client_init(NULL);
        ldapoperation_sasl_initialized = true;
    }
#endif
}

LdapConnection::LdapConnection()
    : d(new LdapConnectionPrivate)
{
    d->mLDAP = 0;
}

LdapConnection::LdapConnection(const LdapUrl &url)
    : d(new LdapConnectionPrivate)
{
    d->mLDAP = 0;
    setUrl(url);
}

LdapConnection::LdapConnection(const LdapServer &server)
    : d(new LdapConnectionPrivate)
{
    d->mLDAP = 0;
    setServer(server);
}

LdapConnection::~LdapConnection()
{
    close();
    delete d;
}

void LdapConnection::setUrl(const LdapUrl &url)
{
    d->mServer.setUrl(url);
}

void LdapConnection::setServer(const LdapServer &server)
{
    d->mServer = server;
}

const LdapServer &LdapConnection::server() const
{
    return d->mServer;
}

void *LdapConnection::handle() const
{
    return (void *)d->mLDAP;
}

void *LdapConnection::saslHandle() const
{
    return (void *)d->mSASLconn;
}

QString LdapConnection::errorString(int code)
{
    //No translated error messages yet
#ifdef LDAP_FOUND
    return QString::fromUtf8(ldap_err2string(code));
    switch (code) {
    case LDAP_OPERATIONS_ERROR:
        return i18n("LDAP Operations error");
        //FIXME:
        /* add the LDAP error codes */
    }
#else
    return i18n("No LDAP Support...");
#endif
}

QString LdapConnection::saslErrorString() const
{
#ifdef SASL2_FOUND
    const char *str;
    str = sasl_errdetail(d->mSASLconn);
    return QString::fromLocal8Bit(str);
#else
    return i18n("SASL support is not available. Please recompile libkldap with the "
                "Cyrus-SASL (or compatible) client libraries, or complain to your "
                "distribution packagers.");
#endif
}

QString LdapConnection::connectionError() const
{
    return d->mConnectionError;
}

#ifdef LDAP_FOUND
int LdapConnection::getOption(int option, void *value) const
{
    Q_ASSERT(d->mLDAP);
    return ldap_get_option(d->mLDAP, option, value);
}

int LdapConnection::setOption(int option, void *value)
{
    Q_ASSERT(d->mLDAP);
    return ldap_set_option(d->mLDAP, option, value);
}

int LdapConnection::ldapErrorCode() const
{
    Q_ASSERT(d->mLDAP);
    int err;
    ldap_get_option(d->mLDAP, LDAP_OPT_ERROR_NUMBER, &err);
    return err;
}

QString LdapConnection::ldapErrorString() const
{
    Q_ASSERT(d->mLDAP);
    char *errmsg;
    ldap_get_option(d->mLDAP, LDAP_OPT_ERROR_STRING, &errmsg);
    QString msg = QString::fromLocal8Bit(errmsg);
    free(errmsg);
    return msg;
}

bool LdapConnection::setSizeLimit(int sizelimit)
{
    Q_ASSERT(d->mLDAP);
    qDebug() << "sizelimit:" << sizelimit;
    if (setOption(LDAP_OPT_SIZELIMIT, &sizelimit) != LDAP_OPT_SUCCESS) {
        return false;
    }
    return true;
}

int LdapConnection::sizeLimit() const
{
    Q_ASSERT(d->mLDAP);
    int sizelimit;
    if (getOption(LDAP_OPT_SIZELIMIT, &sizelimit) != LDAP_OPT_SUCCESS) {
        return -1;
    }
    return sizelimit;
}

bool LdapConnection::setTimeLimit(int timelimit)
{
    Q_ASSERT(d->mLDAP);
    qDebug() << "timelimit:" << timelimit;
    if (setOption(LDAP_OPT_TIMELIMIT, &timelimit) != LDAP_OPT_SUCCESS) {
        return false;
    }
    return true;
}

int LdapConnection::timeLimit() const
{
    Q_ASSERT(d->mLDAP);
    int timelimit;
    if (getOption(LDAP_OPT_TIMELIMIT, &timelimit) != LDAP_OPT_SUCCESS) {
        return -1;
    }
    return timelimit;
}

int LdapConnection::connect()
{
    int ret;
    QString url;
    if (d->mLDAP) {
        close();
    }

    int version = d->mServer.version();
    int timeout = d->mServer.timeout();

    url = d->mServer.security() == LdapServer::SSL ? QLatin1String("ldaps") : QLatin1String("ldap");
    url += QLatin1String("://");
    url += d->mServer.host();
    url += QLatin1Char(':');
    url += QString::number(d->mServer.port());
    qDebug() << "ldap url:" << url;
#ifdef HAVE_LDAP_INITIALIZE
    ret = ldap_initialize(&d->mLDAP, url.toLatin1().constData());
#else
    d->mLDAP = ldap_init(d->mServer.host().toLatin1().data(), d->mServer.port());
    if (d->mLDAP == 0) {
        ret = -1;
    } else {
        ret = LDAP_SUCCESS;
    }
#endif
    if (ret != LDAP_SUCCESS) {
        d->mConnectionError = i18n("An error occurred during the connection initialization phase.");
        return ret;
    }

    qDebug() << "setting version to:" << version;
    if (setOption(LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
        ret = ldapErrorCode();
        d->mConnectionError = i18n("Cannot set protocol version to %1.", version);
        close();
        return ret;
    }

#if defined(LDAP_OPT_TIMEOUT)
    qDebug() << "setting timeout to:" << timeout;

    if (timeout) {
        if (setOption(LDAP_OPT_TIMEOUT, &timeout) != LDAP_OPT_SUCCESS) {
            ret = ldapErrorCode();
            d->mConnectionError = i18np("Cannot set timeout to %1 second.",
                                        "Cannot set timeout to %1 seconds.",
                                        timeout);
            close();
            return ret;
        }
    }
#endif

    //FIXME: accessing to certificate handling would be good
    qDebug() << "setting security to:" << d->mServer.security();
    if (d->mServer.security() == LdapServer::TLS) {
        qDebug() << "start TLS";
#ifdef HAVE_LDAP_START_TLS_S
        if ((ret = ldap_start_tls_s(d->mLDAP, NULL, NULL)) != LDAP_SUCCESS) {
            d->mConnectionError = ldapErrorString();
            close();
            return ret;
        }
#else
        close();
        d->mConnectionError = i18n("TLS support not available in the LDAP client libraries.");
        return -1;
#endif
    }

    qDebug() << "setting sizelimit to:" << d->mServer.sizeLimit();
    if (d->mServer.sizeLimit()) {
        if (!setSizeLimit(d->mServer.sizeLimit())) {
            ret = ldapErrorCode();
            close();
            d->mConnectionError = i18n("Cannot set size limit.");
            return ret;
        }
    }

    qDebug() << "setting timelimit to:" << d->mServer.timeLimit();
    if (d->mServer.timeLimit()) {
        if (!setTimeLimit(d->mServer.timeLimit())) {
            ret = ldapErrorCode();
            close();
            d->mConnectionError = i18n("Cannot set time limit.");
            return ret;
        }
    }

#ifdef SASL2_FOUND
    qDebug() << "initializing SASL client";
    int saslresult = sasl_client_new("ldap", d->mServer.host().toLatin1(),
                                     0, 0, callbacks, 0, &d->mSASLconn);
    if (saslresult != SASL_OK) {
        d->mConnectionError = i18n("Cannot initialize the SASL client.");
        return KLDAP_SASL_ERROR;
    }
#endif

    return 0;
}

void LdapConnection::close()
{
    if (d->mLDAP) {
#ifdef HAVE_LDAP_UNBIND_EXT
        ldap_unbind_ext(d->mLDAP, 0, 0);
#else
        ldap_unbind(d->mLDAP);
#endif
    }
    d->mLDAP = 0;
#ifdef SASL2_FOUND
    if (d->mSASLconn) {
        sasl_dispose(&d->mSASLconn);
        d->mSASLconn = 0;
    }
#endif
    qDebug() << "connection closed!";
}
#else //LDAP_FOUND

int LdapConnection::getOption(int option, void *value) const
{
    qCritical() << "No LDAP support...";
    return -1;
}

int LdapConnection::setOption(int option, void *value)
{
    qCritical() << "No LDAP support...";
    return -1;
}

int LdapConnection::ldapErrorCode() const
{
    qCritical() << "No LDAP support...";
    return -1;
}

QString LdapConnection::ldapErrorString() const
{
    qCritical() << "No LDAP support...";
    return QString();
}

bool LdapConnection::setSizeLimit(int sizelimit)
{
    qCritical() << "No LDAP support...";
    return false;
}

int LdapConnection::sizeLimit() const
{
    qCritical() << "No LDAP support...";
    return -1;
}

bool LdapConnection::setTimeLimit(int timelimit)
{
    qCritical() << "No LDAP support...";
    return false;
}

int LdapConnection::timeLimit() const
{
    qCritical() << "No LDAP support...";
    return -1;
}

int LdapConnection::connect()
{
    d->mConnectionError =
        i18n("LDAP support not compiled in. Please recompile libkldap with the "
             "OpenLDAP (or compatible) client libraries, or complain to your "
             "distribution packagers.");
    qCritical() << "No LDAP support...";
    return -1;
}

void LdapConnection::close()
{
    qCritical() << "No LDAP support...";
}

#endif
