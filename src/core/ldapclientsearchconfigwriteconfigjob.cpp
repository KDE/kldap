/*
 * SPDX-FileCopyrightText: 2020-2026 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfigwriteconfigjob.h"
#include "ldap_core_debug.h"

#include "kldapcore/ldapdn.h"
#include <qt6keychain/keychain.h>
using namespace QKeychain;
using namespace Qt::Literals::StringLiterals;
using namespace KLDAPCore;
LdapClientSearchConfigWriteConfigJob::LdapClientSearchConfigWriteConfigJob(QObject *parent)
    : QObject(parent)
{
}

LdapClientSearchConfigWriteConfigJob::~LdapClientSearchConfigWriteConfigJob() = default;

bool LdapClientSearchConfigWriteConfigJob::canStart() const
{
    return mServerIndex != -1 && mConfig.isValid();
}

void LdapClientSearchConfigWriteConfigJob::writeLdapClientConfigFinished()
{
    Q_EMIT configSaved();
    deleteLater();
}

void LdapClientSearchConfigWriteConfigJob::start()
{
    if (!canStart()) {
        // Failed !
        writeLdapClientConfigFinished();
        return;
    }
    writeConfig();
}

bool LdapClientSearchConfigWriteConfigJob::active() const
{
    return mActive;
}

void LdapClientSearchConfigWriteConfigJob::setActive(bool newActive)
{
    mActive = newActive;
}

int LdapClientSearchConfigWriteConfigJob::serverIndex() const
{
    return mServerIndex;
}

void LdapClientSearchConfigWriteConfigJob::setServerIndex(int newServerIndex)
{
    mServerIndex = newServerIndex;
}

KConfigGroup LdapClientSearchConfigWriteConfigJob::config() const
{
    return mConfig;
}

void LdapClientSearchConfigWriteConfigJob::setConfig(const KConfigGroup &newConfig)
{
    mConfig = newConfig;
}

void LdapClientSearchConfigWriteConfigJob::writeConfig()
{
    QString prefix;
    if (mActive) {
        prefix = u"Selected"_s;
    }

    mConfig.writeEntry(prefix + u"Host%1"_s.arg(mServerIndex), mServer.host());
    mConfig.writeEntry(prefix + u"Port%1"_s.arg(mServerIndex), mServer.port());
    mConfig.writeEntry(prefix + u"Base%1"_s.arg(mServerIndex), mServer.baseDn().toString());
    mConfig.writeEntry(prefix + u"User%1"_s.arg(mServerIndex), mServer.user());
    mConfig.writeEntry(prefix + u"Bind%1"_s.arg(mServerIndex), mServer.bindDn());

    const QString passwordEntry = prefix + u"PwdBind%1"_s.arg(mServerIndex);
    const QString password = mServer.password();
    if (!password.isEmpty()) {
        auto writeJob = new WritePasswordJob(u"ldapclient"_s, this);
        connect(writeJob, &Job::finished, this, [](QKeychain::Job *baseJob) {
            if (baseJob->error()) {
                qCWarning(LDAP_CORE_LOG) << "Error writing password using QKeychain:" << baseJob->errorString();
            }
        });
        writeJob->setKey(passwordEntry);
        writeJob->setTextData(password);
        writeJob->start();
    }

    mConfig.writeEntry(prefix + u"TimeLimit%1"_s.arg(mServerIndex), mServer.timeLimit());
    mConfig.writeEntry(prefix + u"SizeLimit%1"_s.arg(mServerIndex), mServer.sizeLimit());
    mConfig.writeEntry(prefix + u"PageSize%1"_s.arg(mServerIndex), mServer.pageSize());
    mConfig.writeEntry(prefix + u"Version%1"_s.arg(mServerIndex), mServer.version());
    mConfig.writeEntry(prefix + u"Activities%1"_s.arg(mServerIndex), mServer.activities());
    mConfig.writeEntry(prefix + u"EnabledActivities%1"_s.arg(mServerIndex), mServer.enablePlasmaActivities());

    QString tmp;
    switch (mServer.security()) {
    case KLDAPCore::LdapServer::TLS:
        tmp = u"TLS"_s;
        break;
    case KLDAPCore::LdapServer::SSL:
        tmp = u"SSL"_s;
        break;
    default:
        tmp = u"None"_s;
    }
    mConfig.writeEntry(prefix + u"Security%1"_s.arg(mServerIndex), tmp);
    switch (mServer.auth()) {
    case KLDAPCore::LdapServer::Simple:
        tmp = u"Simple"_s;
        break;
    case KLDAPCore::LdapServer::SASL:
        tmp = u"SASL"_s;
        break;
    default:
        tmp = u"Anonymous"_s;
    }
    mConfig.writeEntry(prefix + u"Auth%1"_s.arg(mServerIndex), tmp);
    mConfig.writeEntry(prefix + u"Mech%1"_s.arg(mServerIndex), mServer.mech());
    mConfig.writeEntry(prefix + u"UserFilter%1"_s.arg(mServerIndex), mServer.filter().trimmed());
    if (mServer.completionWeight() > -1) {
        mConfig.writeEntry(prefix + u"CompletionWeight%1"_s.arg(mServerIndex), mServer.completionWeight());
    }
}

KLDAPCore::LdapServer LdapClientSearchConfigWriteConfigJob::server() const
{
    return mServer;
}

void LdapClientSearchConfigWriteConfigJob::setServer(const KLDAPCore::LdapServer &server)
{
    mServer = server;
}

#include "moc_ldapclientsearchconfigwriteconfigjob.cpp"
