/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapconnection.h"
#include "kldap_config.h" // LDAP_FOUND
#include "ldapdefs.h"

#include "ldap_core_debug.h"
#include <KLocalizedString>
#include <cstdlib>

#include <sasl/sasl.h>
static const sasl_callback_t callbacks[] = {{SASL_CB_ECHOPROMPT, nullptr, nullptr},
                                            {SASL_CB_NOECHOPROMPT, nullptr, nullptr},
                                            {SASL_CB_GETREALM, nullptr, nullptr},
                                            {SASL_CB_USER, nullptr, nullptr},
                                            {SASL_CB_AUTHNAME, nullptr, nullptr},
                                            {SASL_CB_PASS, nullptr, nullptr},
                                            {SASL_CB_CANON_USER, nullptr, nullptr},
                                            {SASL_CB_LIST_END, nullptr, nullptr}};

static bool ldapoperation_sasl_initialized = false;

#if LDAP_FOUND
#if !HAVE_WINLDAP_H
#include <lber.h>
#include <ldap.h>
#else
#include <w32-ldap-help.h>
#endif // HAVE_WINLDAP_H

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS 0
#endif

#endif

using namespace KLDAPCore;

class Q_DECL_HIDDEN LdapConnection::LdapConnectionPrivate
{
public:
    LdapConnectionPrivate();
    LdapServer mServer;
    QString mConnectionError;

#if LDAP_FOUND
    LDAP *mLDAP;
#else
    void *mLDAP;
#endif
    sasl_conn_t *mSASLconn;
};

LdapConnection::LdapConnectionPrivate::LdapConnectionPrivate()
{
    mSASLconn = nullptr;
    if (!ldapoperation_sasl_initialized) {
        sasl_client_init(nullptr);
        ldapoperation_sasl_initialized = true;
    }
}

LdapConnection::LdapConnection()
    : d(new LdapConnectionPrivate)
{
    d->mLDAP = nullptr;
}

LdapConnection::LdapConnection(const LdapUrl &url)
    : d(new LdapConnectionPrivate)
{
    d->mLDAP = nullptr;
    setUrl(url);
}

LdapConnection::LdapConnection(const LdapServer &server)
    : d(new LdapConnectionPrivate)
{
    d->mLDAP = nullptr;
    setServer(server);
}

LdapConnection::~LdapConnection()
{
    close();
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
    // No translated error messages yet
#if LDAP_FOUND
    return QString::fromUtf8(ldap_err2string(code));
#else
    return i18n("No LDAP Support...");
#endif
}

QString LdapConnection::saslErrorString() const
{
    const char *str;
    str = sasl_errdetail(d->mSASLconn);
    return QString::fromLocal8Bit(str);
}

QString LdapConnection::connectionError() const
{
    return d->mConnectionError;
}

#if LDAP_FOUND
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
    qCDebug(LDAP_LOG) << "sizelimit:" << sizelimit;
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
    qCDebug(LDAP_LOG) << "timelimit:" << timelimit;
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

    url = d->mServer.security() == LdapServer::SSL ? QStringLiteral("ldaps") : QStringLiteral("ldap");
    url += QLatin1String("://");
    url += d->mServer.host();
    url += QLatin1Char(':');
    url += QString::number(d->mServer.port());
    qCDebug(LDAP_LOG) << "ldap url:" << url;
#if HAVE_LDAP_INITIALIZE
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

    qCDebug(LDAP_LOG) << "setting version to:" << version;
    if (setOption(LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
        ret = ldapErrorCode();
        d->mConnectionError = i18n("Cannot set protocol version to %1.", version);
        close();
        return ret;
    }

#if defined(LDAP_OPT_TIMEOUT)
    qCDebug(LDAP_LOG) << "setting timeout to:" << timeout;

    if (timeout) {
        if (setOption(LDAP_OPT_TIMEOUT, &timeout) != LDAP_OPT_SUCCESS) {
            ret = ldapErrorCode();
            d->mConnectionError = i18np("Cannot set timeout to %1 second.", "Cannot set timeout to %1 seconds.", timeout);
            close();
            return ret;
        }
    }
#endif

    qCDebug(LDAP_LOG) << "setting security to:" << d->mServer.security();
    if (d->mServer.security() != LdapServer::None) {
        bool initContext = false;
        if (d->mServer.tlsCACertFile().isEmpty() == false) {
            if (setOption(LDAP_OPT_X_TLS_CACERTFILE, d->mServer.tlsCACertFile().toUtf8().data()) != LDAP_OPT_SUCCESS) {
                d->mConnectionError = i18n("Could not set CA certificate file.");
                return -1;
            }
            initContext = true;
        }

        if (d->mServer.tlsRequireCertificate() != LdapServer::TLSReqCertDefault) {
            int reqcert;
            switch (d->mServer.tlsRequireCertificate()) {
            case LdapServer::TLSReqCertAllow:
                reqcert = LDAP_OPT_X_TLS_ALLOW;
                break;
            case LdapServer::TLSReqCertDemand:
                reqcert = LDAP_OPT_X_TLS_DEMAND;
                break;
            case LdapServer::TLSReqCertHard:
                reqcert = LDAP_OPT_X_TLS_HARD;
                break;
            case LdapServer::TLSReqCertNever:
                reqcert = LDAP_OPT_X_TLS_NEVER;
                break;
            case LdapServer::TLSReqCertTry:
                reqcert = LDAP_OPT_X_TLS_TRY;
                break;
            default:
                d->mConnectionError = i18n("Invalid TLS require certificate mode.");
                return -1;
            }

            if (setOption(LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert) != LDAP_OPT_SUCCESS) {
                d->mConnectionError = i18n("Could not set TLS require certificate mode.");
                return -1;
            }
            initContext = true;
        }

        if (initContext) {
            int isServer = 0;
            if (setOption(LDAP_OPT_X_TLS_NEWCTX, &isServer) != LDAP_OPT_SUCCESS) {
                d->mConnectionError = i18n("Could not initialize new TLS context.");
                return -1;
            }
        }
    }

    if (d->mServer.security() == LdapServer::TLS) {
        qCDebug(LDAP_LOG) << "start TLS";

#if HAVE_LDAP_START_TLS_S
        if ((ret = ldap_start_tls_s(d->mLDAP, nullptr, nullptr)) != LDAP_SUCCESS) {
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

    qCDebug(LDAP_LOG) << "setting sizelimit to:" << d->mServer.sizeLimit();
    if (d->mServer.sizeLimit()) {
        if (!setSizeLimit(d->mServer.sizeLimit())) {
            ret = ldapErrorCode();
            close();
            d->mConnectionError = i18n("Cannot set size limit.");
            return ret;
        }
    }

    qCDebug(LDAP_LOG) << "setting timelimit to:" << d->mServer.timeLimit();
    if (d->mServer.timeLimit()) {
        if (!setTimeLimit(d->mServer.timeLimit())) {
            ret = ldapErrorCode();
            close();
            d->mConnectionError = i18n("Cannot set time limit.");
            return ret;
        }
    }

    qCDebug(LDAP_LOG) << "initializing SASL client";
    const int saslresult = sasl_client_new("ldap", d->mServer.host().toLatin1().constData(), nullptr, nullptr, callbacks, 0, &d->mSASLconn);
    if (saslresult != SASL_OK) {
        d->mConnectionError = i18n("Cannot initialize the SASL client.");
        return KLDAP_SASL_ERROR;
    }

    return 0;
}

void LdapConnection::close()
{
    if (d->mLDAP) {
#if HAVE_LDAP_UNBIND_EXT
        ldap_unbind_ext(d->mLDAP, nullptr, nullptr);
#else
        ldap_unbind(d->mLDAP);
#endif
    }
    d->mLDAP = nullptr;
    if (d->mSASLconn) {
        sasl_dispose(&d->mSASLconn);
        d->mSASLconn = nullptr;
    }
    qCDebug(LDAP_LOG) << "connection closed!";
}

#else // LDAP_FOUND

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
    d->mConnectionError = i18n(
        "LDAP support not compiled in. Please recompile libkldap with the "
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
