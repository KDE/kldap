/*
 * SPDX-FileCopyrightText: 2020-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfigwriteconfigjob.h"
#include "ldapclient_debug.h"

#include <kldapcore/ldapdn.h>
#include <qt6keychain/keychain.h>
using namespace QKeychain;

using namespace KLDAPWidgets;
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
        prefix = QStringLiteral("Selected");
    }

    mConfig.writeEntry(prefix + QStringLiteral("Host%1").arg(mServerIndex), mServer.host());
    mConfig.writeEntry(prefix + QStringLiteral("Port%1").arg(mServerIndex), mServer.port());
    mConfig.writeEntry(prefix + QStringLiteral("Base%1").arg(mServerIndex), mServer.baseDn().toString());
    mConfig.writeEntry(prefix + QStringLiteral("User%1").arg(mServerIndex), mServer.user());
    mConfig.writeEntry(prefix + QStringLiteral("Bind%1").arg(mServerIndex), mServer.bindDn());

    const QString passwordEntry = prefix + QStringLiteral("PwdBind%1").arg(mServerIndex);
    const QString password = mServer.password();
    if (!password.isEmpty()) {
        auto writeJob = new WritePasswordJob(QStringLiteral("ldapclient"), this);
        connect(writeJob, &Job::finished, this, [](QKeychain::Job *baseJob) {
            if (baseJob->error()) {
                qCWarning(LDAPCLIENT_LOG) << "Error writing password using QKeychain:" << baseJob->errorString();
            }
        });
        writeJob->setKey(passwordEntry);
        writeJob->setTextData(password);
        writeJob->start();
    }

    mConfig.writeEntry(prefix + QStringLiteral("TimeLimit%1").arg(mServerIndex), mServer.timeLimit());
    mConfig.writeEntry(prefix + QStringLiteral("SizeLimit%1").arg(mServerIndex), mServer.sizeLimit());
    mConfig.writeEntry(prefix + QStringLiteral("PageSize%1").arg(mServerIndex), mServer.pageSize());
    mConfig.writeEntry(prefix + QStringLiteral("Version%1").arg(mServerIndex), mServer.version());
    QString tmp;
    switch (mServer.security()) {
    case KLDAPCore::LdapServer::TLS:
        tmp = QStringLiteral("TLS");
        break;
    case KLDAPCore::LdapServer::SSL:
        tmp = QStringLiteral("SSL");
        break;
    default:
        tmp = QStringLiteral("None");
    }
    mConfig.writeEntry(prefix + QStringLiteral("Security%1").arg(mServerIndex), tmp);
    switch (mServer.auth()) {
    case KLDAPCore::LdapServer::Simple:
        tmp = QStringLiteral("Simple");
        break;
    case KLDAPCore::LdapServer::SASL:
        tmp = QStringLiteral("SASL");
        break;
    default:
        tmp = QStringLiteral("Anonymous");
    }
    mConfig.writeEntry(prefix + QStringLiteral("Auth%1").arg(mServerIndex), tmp);
    mConfig.writeEntry(prefix + QStringLiteral("Mech%1").arg(mServerIndex), mServer.mech());
    mConfig.writeEntry(prefix + QStringLiteral("UserFilter%1").arg(mServerIndex), mServer.filter().trimmed());
    if (mServer.completionWeight() > -1) {
        mConfig.writeEntry(prefix + QStringLiteral("CompletionWeight%1").arg(mServerIndex), mServer.completionWeight());
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
