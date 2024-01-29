/*
 * SPDX-FileCopyrightText: 2020-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfigreadconfigjob.h"
#include "ldapclient_debug.h"

#include <KConfig>
#include <KLocalizedString>
#include <kldapcore/ldapdn.h>
#include <qt6keychain/keychain.h>
using namespace QKeychain;

using namespace KLDAPWidgets;
LdapClientSearchConfigReadConfigJob::LdapClientSearchConfigReadConfigJob(QObject *parent)
    : QObject(parent)
{
}

LdapClientSearchConfigReadConfigJob::~LdapClientSearchConfigReadConfigJob() = default;

bool LdapClientSearchConfigReadConfigJob::canStart() const
{
    return mServerIndex != -1 && mConfig.isValid();
}

void LdapClientSearchConfigReadConfigJob::readLdapClientConfigFinished()
{
    Q_EMIT configLoaded(mServer);
    deleteLater();
}

void LdapClientSearchConfigReadConfigJob::start()
{
    if (!canStart()) {
        // Failed !
        readLdapClientConfigFinished();
        return;
    }
    readConfig();
}

bool LdapClientSearchConfigReadConfigJob::active() const
{
    return mActive;
}

void LdapClientSearchConfigReadConfigJob::setActive(bool newActive)
{
    mActive = newActive;
}

int LdapClientSearchConfigReadConfigJob::serverIndex() const
{
    return mServerIndex;
}

void LdapClientSearchConfigReadConfigJob::setServerIndex(int newServerIndex)
{
    mServerIndex = newServerIndex;
}

KConfigGroup LdapClientSearchConfigReadConfigJob::config() const
{
    return mConfig;
}

void LdapClientSearchConfigReadConfigJob::setConfig(const KConfigGroup &newConfig)
{
    mConfig = newConfig;
}

void LdapClientSearchConfigReadConfigJob::readConfig()
{
    QString prefix;
    if (mActive) {
        prefix = QStringLiteral("Selected");
    }

    const QString host = mConfig.readEntry(prefix + QStringLiteral("Host%1").arg(mServerIndex), QString()).trimmed();
    if (!host.isEmpty()) {
        mServer.setHost(host);
    }

    const int port = mConfig.readEntry(prefix + QStringLiteral("Port%1").arg(mServerIndex), 389);
    mServer.setPort(port);

    const QString base = mConfig.readEntry(prefix + QStringLiteral("Base%1").arg(mServerIndex), QString()).trimmed();
    if (!base.isEmpty()) {
        mServer.setBaseDn(KLDAPCore::LdapDN(base));
    }

    const QString user = mConfig.readEntry(prefix + QStringLiteral("User%1").arg(mServerIndex), QString()).trimmed();
    if (!user.isEmpty()) {
        mServer.setUser(user);
    }

    const QString bindDN = mConfig.readEntry(prefix + QStringLiteral("Bind%1").arg(mServerIndex), QString()).trimmed();
    if (!bindDN.isEmpty()) {
        mServer.setBindDn(bindDN);
    }
    mServer.setTimeLimit(mConfig.readEntry(prefix + QStringLiteral("TimeLimit%1").arg(mServerIndex), 0));
    mServer.setSizeLimit(mConfig.readEntry(prefix + QStringLiteral("SizeLimit%1").arg(mServerIndex), 0));
    mServer.setPageSize(mConfig.readEntry(prefix + QStringLiteral("PageSize%1").arg(mServerIndex), 0));
    mServer.setVersion(mConfig.readEntry(prefix + QStringLiteral("Version%1").arg(mServerIndex), 3));

    QString tmp = mConfig.readEntry(prefix + QStringLiteral("Security%1").arg(mServerIndex), QStringLiteral("None"));
    mServer.setSecurity(KLDAPCore::LdapServer::None);
    if (tmp == QLatin1StringView("SSL")) {
        mServer.setSecurity(KLDAPCore::LdapServer::SSL);
    } else if (tmp == QLatin1StringView("TLS")) {
        mServer.setSecurity(KLDAPCore::LdapServer::TLS);
    }

    tmp = mConfig.readEntry(prefix + QStringLiteral("Auth%1").arg(mServerIndex), QStringLiteral("Anonymous"));
    mServer.setAuth(KLDAPCore::LdapServer::Anonymous);
    if (tmp == QLatin1StringView("Simple")) {
        mServer.setAuth(KLDAPCore::LdapServer::Simple);
    } else if (tmp == QLatin1StringView("SASL")) {
        mServer.setAuth(KLDAPCore::LdapServer::SASL);
    }

    mServer.setMech(mConfig.readEntry(prefix + QStringLiteral("Mech%1").arg(mServerIndex), QString()));
    mServer.setFilter(mConfig.readEntry(prefix + QStringLiteral("UserFilter%1").arg(mServerIndex), QString()));
    mServer.setCompletionWeight(mConfig.readEntry(prefix + QStringLiteral("CompletionWeight%1").arg(mServerIndex), -1));

    const QString pwdBindBNEntry = prefix + QStringLiteral("PwdBind%1").arg(mServerIndex);

    auto readJob = new ReadPasswordJob(QStringLiteral("ldapclient"), this);
    connect(readJob, &Job::finished, this, [this, pwdBindBNEntry](QKeychain::Job *baseJob) {
        auto job = qobject_cast<ReadPasswordJob *>(baseJob);
        Q_ASSERT(job);
        if (!job->error()) {
            mServer.setPassword(job->textData());
        } else {
            qCWarning(LDAPCLIENT_LOG) << "We have an error during reading password " << job->errorString() << " password key " << pwdBindBNEntry;
        }
        readLdapClientConfigFinished();
    });
    readJob->setKey(pwdBindBNEntry);
    readJob->start();
}

#include "moc_ldapclientsearchconfigreadconfigjob.cpp"
