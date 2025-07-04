/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapserver.h"
using namespace Qt::Literals::StringLiterals;

#include "ldap_core_debug.h"

using namespace KLDAPCore;

class Q_DECL_HIDDEN LdapServer::LdapServerPrivate
{
public:
    QString mHost;
    int mPort;
    LdapDN mBaseDn;
    QString mUser;
    QString mBindDn;
    QString mRealm;
    QString mPassword;
    QString mMech;
    QString mFilter;
    int mTimeLimit;
    int mSizeLimit;
    int mVersion;
    int mPageSize;
    int mTimeout;
    Security mSecurity;
    Auth mAuth;
    QString mTLSCACertFile;
    TLSRequireCertificate mTLSRequireCertificate;
    LdapUrl::Scope mScope;
    int mCompletionWeight = -1;
    QStringList mActivities;
    bool mEnablePlasmaActivities = false;
};

LdapServer::LdapServer()
    : d(new LdapServerPrivate)
{
    clear();
}

LdapServer::LdapServer(const LdapUrl &url)
    : d(new LdapServerPrivate)
{
    clear();

    setUrl(url);
}

LdapServer::LdapServer(const LdapServer &that)
    : d(new LdapServerPrivate)
{
    *d = *that.d;
}

LdapServer &LdapServer::operator=(const LdapServer &that)
{
    if (this == &that) {
        return *this;
    }

    *d = *that.d;

    return *this;
}

LdapServer::~LdapServer() = default;

void LdapServer::clear()
{
    d->mPort = 389;
    d->mHost.clear();
    d->mUser.clear();
    d->mBindDn.clear();
    d->mMech.clear();
    d->mPassword.clear();
    d->mSecurity = None;
    d->mAuth = Anonymous;
    d->mTLSRequireCertificate = TLSReqCertDefault;
    d->mTLSCACertFile.clear();
    d->mVersion = 3;
    d->mTimeout = 0;
    d->mSizeLimit = d->mTimeLimit = d->mPageSize = 0;
    d->mCompletionWeight = -1;
    d->mActivities.clear();
    d->mEnablePlasmaActivities = false;
}

QString LdapServer::host() const
{
    return d->mHost;
}

int LdapServer::port() const
{
    return d->mPort;
}

LdapDN LdapServer::baseDn() const
{
    return d->mBaseDn;
}

QString LdapServer::user() const
{
    return d->mUser;
}

QString LdapServer::bindDn() const
{
    return d->mBindDn;
}

QString LdapServer::realm() const
{
    return d->mRealm;
}

QString LdapServer::password() const
{
    return d->mPassword;
}

QString LdapServer::filter() const
{
    return d->mFilter;
}

LdapUrl::Scope LdapServer::scope() const
{
    return d->mScope;
}

int LdapServer::timeLimit() const
{
    return d->mTimeLimit;
}

int LdapServer::sizeLimit() const
{
    return d->mSizeLimit;
}

int LdapServer::pageSize() const
{
    return d->mPageSize;
}

int LdapServer::version() const
{
    return d->mVersion;
}

LdapServer::Security LdapServer::security() const
{
    return d->mSecurity;
}

LdapServer::Auth LdapServer::auth() const
{
    return d->mAuth;
}

LdapServer::TLSRequireCertificate LdapServer::tlsRequireCertificate() const
{
    return d->mTLSRequireCertificate;
}

QString LdapServer::tlsCACertFile() const
{
    return d->mTLSCACertFile;
}

QString LdapServer::mech() const
{
    return d->mMech;
}

int LdapServer::timeout() const
{
    return d->mTimeout;
}

void LdapServer::setHost(const QString &host)
{
    d->mHost = host;
}

void LdapServer::setPort(int port)
{
    d->mPort = port;
}

void LdapServer::setBaseDn(const LdapDN &baseDn)
{
    d->mBaseDn = baseDn;
}

void LdapServer::setUser(const QString &user)
{
    d->mUser = user;
}

void LdapServer::setBindDn(const QString &bindDn)
{
    d->mBindDn = bindDn;
}

void LdapServer::setRealm(const QString &realm)
{
    d->mRealm = realm;
}

void LdapServer::setPassword(const QString &password)
{
    d->mPassword = password;
}

void LdapServer::setTimeLimit(int timelimit)
{
    d->mTimeLimit = timelimit;
}

void LdapServer::setSizeLimit(int sizelimit)
{
    d->mSizeLimit = sizelimit;
}

void LdapServer::setPageSize(int pagesize)
{
    d->mPageSize = pagesize;
}

void LdapServer::setFilter(const QString &filter)
{
    d->mFilter = filter;
}

void LdapServer::setScope(LdapUrl::Scope scope)
{
    d->mScope = scope;
}

void LdapServer::setVersion(int version)
{
    d->mVersion = version;
}

void LdapServer::setSecurity(Security security)
{
    d->mSecurity = security;
}

void LdapServer::setAuth(Auth auth)
{
    d->mAuth = auth;
}

void LdapServer::setTLSRequireCertificate(LdapServer::TLSRequireCertificate reqCert)
{
    d->mTLSRequireCertificate = reqCert;
}

void LdapServer::setTLSCACertFile(const QString &caCertFile)
{
    d->mTLSCACertFile = caCertFile;
}

void LdapServer::setMech(const QString &mech)
{
    d->mMech = mech;
}

void LdapServer::setTimeout(int timeout)
{
    d->mTimeout = timeout;
}

void LdapServer::setUrl(const LdapUrl &url)
{
    bool critical = true;

    d->mHost = url.host();
    const int port = url.port();
    if (port <= 0) {
        d->mPort = 389;
    } else {
        d->mPort = port;
    }
    d->mBaseDn = url.dn();
    d->mScope = url.scope();

    d->mFilter = url.filter();

    d->mSecurity = None;
    if (url.scheme() == "ldaps"_L1) {
        d->mSecurity = SSL;
    } else if (url.hasExtension(u"x-tls"_s)) {
        d->mSecurity = TLS;
    }
    qCDebug(LDAP_CORE_LOG) << "security:" << d->mSecurity;

    d->mMech.clear();
    d->mUser.clear();
    d->mBindDn.clear();
    if (url.hasExtension(u"x-sasl"_s)) {
        d->mAuth = SASL;
        if (url.hasExtension(u"x-mech"_s)) {
            d->mMech = url.extension(u"x-mech"_s, critical);
        }
        if (url.hasExtension(u"x-realm"_s)) {
            d->mRealm = url.extension(u"x-realm"_s, critical);
        }
        if (url.hasExtension(u"bindname"_s)) {
            d->mBindDn = url.extension(u"bindname"_s, critical);
        }
        d->mUser = url.userName();
    } else if (url.hasExtension(u"bindname"_s)) {
        d->mAuth = Simple;
        d->mBindDn = url.extension(u"bindname"_s, critical);
    } else {
        const QString user = url.userName();
        if (user.isEmpty()) {
            d->mAuth = Anonymous;
        } else {
            d->mAuth = Simple;
            d->mBindDn = user;
        }
    }
    d->mPassword = url.password();
    if (url.hasExtension(u"x-version"_s)) {
        d->mVersion = url.extension(u"x-version"_s, critical).toInt();
    } else {
        d->mVersion = 3;
    }

    if (url.hasExtension(u"x-timeout"_s)) {
        d->mTimeout = url.extension(u"x-timeout"_s, critical).toInt();
    } else {
        d->mTimeout = 0;
    }

    if (url.hasExtension(u"x-timelimit"_s)) {
        d->mTimeLimit = url.extension(u"x-timelimit"_s, critical).toInt();
    } else {
        d->mTimeLimit = 0;
    }

    if (url.hasExtension(u"x-sizelimit"_s)) {
        d->mSizeLimit = url.extension(u"x-sizelimit"_s, critical).toInt();
    } else {
        d->mSizeLimit = 0;
    }

    if (url.hasExtension(u"x-pagesize"_s)) {
        d->mPageSize = url.extension(u"x-pagesize"_s, critical).toInt();
    } else {
        d->mPageSize = 0;
    }
}

LdapUrl LdapServer::url() const
{
    LdapUrl url;
    url.setScheme(d->mSecurity == SSL ? u"ldaps"_s : u"ldap"_s);
    url.setPort(d->mPort);
    url.setHost(d->mHost);
    url.setDn(d->mBaseDn);
    url.setFilter(d->mFilter);
    url.setScope(d->mScope);
    if (d->mAuth == SASL) {
        url.setUserName(d->mUser);
        url.setPassword(d->mPassword);
        url.setExtension(u"bindname"_s, d->mBindDn, true);
        url.setExtension(u"x-sasl"_s, QString());
        if (!d->mMech.isEmpty()) {
            url.setExtension(u"x-mech"_s, d->mMech);
        }
        if (!d->mRealm.isEmpty()) {
            url.setExtension(u"x-realm"_s, d->mRealm);
        }
    } else if (d->mAuth == Simple) {
        url.setUserName(d->mBindDn);
        url.setPassword(d->mPassword);
    }
    if (d->mVersion == 2) {
        url.setExtension(u"x-version"_s, d->mVersion);
    }
    if (d->mTimeout) {
        url.setExtension(u"x-timeout"_s, d->mTimeout);
    }
    if (d->mTimeLimit != 0) {
        url.setExtension(u"x-timelimit"_s, d->mTimeLimit);
    }
    if (d->mSizeLimit != 0) {
        url.setExtension(u"x-sizelimit"_s, d->mSizeLimit);
    }
    if (d->mPageSize != 0) {
        url.setExtension(u"x-pagesize"_s, d->mPageSize);
    }
    if (d->mSecurity == TLS) {
        url.setExtension(u"x-tls"_s, 1, true);
    }
    return url;
}

void LdapServer::setCompletionWeight(int value)
{
    d->mCompletionWeight = value;
}

int LdapServer::completionWeight() const
{
    return d->mCompletionWeight;
}

void LdapServer::setActivities(const QStringList &lst)
{
    d->mActivities = lst;
}

QStringList LdapServer::activities() const
{
    return d->mActivities;
}

void LdapServer::setEnablePlasmaActivities(bool enabled)
{
    d->mEnablePlasmaActivities = enabled;
}

bool LdapServer::enablePlasmaActivities() const
{
    return d->mEnablePlasmaActivities;
}

QDebug operator<<(QDebug d, const KLDAPCore::LdapServer &t)
{
    d << "port " << t.port();
    d << "host " << t.host();
    d << "user " << t.user();
    d << "bindDn " << t.bindDn();
    d << "mech " << t.mech();
    d << "security " << t.security();
    d << "auth " << t.auth();
    d << "tlsRequireCertificate " << t.tlsRequireCertificate();
    d << "tlsCACertFile " << t.tlsCACertFile();
    d << "version " << t.version();
    d << "completionWeight " << t.completionWeight();
    d << "timeout " << t.timeout();
    d << "timeLimit " << t.timeLimit();
    d << "sizeLimit " << t.sizeLimit();
    d << "activities " << t.activities();
    d << "enablePlasmaActivities " << t.enablePlasmaActivities();
    return d;
}
