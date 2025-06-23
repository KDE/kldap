/*
 * SPDX-FileCopyrightText: 2020-2025 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfigreadconfigjob.h"

#include "ldap_core_debug.h"

#include "kldapcore/ldapdn.h"
#include <KConfig>
#include <KLocalizedString>
#include <qt6keychain/keychain.h>
using namespace QKeychain;
using namespace Qt::Literals::StringLiterals;

using namespace KLDAPCore;
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
        prefix = u"Selected"_s;
    }

    const QString host = mConfig.readEntry(prefix + u"Host%1"_s.arg(mServerIndex), QString()).trimmed();
    if (!host.isEmpty()) {
        mServer.setHost(host);
    }

    const int port = mConfig.readEntry(prefix + u"Port%1"_s.arg(mServerIndex), 389);
    mServer.setPort(port);

    const QString base = mConfig.readEntry(prefix + u"Base%1"_s.arg(mServerIndex), QString()).trimmed();
    if (!base.isEmpty()) {
        mServer.setBaseDn(KLDAPCore::LdapDN(base));
    }

    const QString user = mConfig.readEntry(prefix + u"User%1"_s.arg(mServerIndex), QString()).trimmed();
    if (!user.isEmpty()) {
        mServer.setUser(user);
    }

    const QString bindDN = mConfig.readEntry(prefix + u"Bind%1"_s.arg(mServerIndex), QString()).trimmed();
    if (!bindDN.isEmpty()) {
        mServer.setBindDn(bindDN);
    }
    mServer.setTimeLimit(mConfig.readEntry(prefix + u"TimeLimit%1"_s.arg(mServerIndex), 0));
    mServer.setSizeLimit(mConfig.readEntry(prefix + u"SizeLimit%1"_s.arg(mServerIndex), 0));
    mServer.setPageSize(mConfig.readEntry(prefix + u"PageSize%1"_s.arg(mServerIndex), 0));
    mServer.setVersion(mConfig.readEntry(prefix + u"Version%1"_s.arg(mServerIndex), 3));

    QString tmp = mConfig.readEntry(prefix + u"Security%1"_s.arg(mServerIndex), u"None"_s);
    mServer.setSecurity(KLDAPCore::LdapServer::None);
    if (tmp == "SSL"_L1) {
        mServer.setSecurity(KLDAPCore::LdapServer::SSL);
    } else if (tmp == "TLS"_L1) {
        mServer.setSecurity(KLDAPCore::LdapServer::TLS);
    }

    tmp = mConfig.readEntry(prefix + u"Auth%1"_s.arg(mServerIndex), u"Anonymous"_s);
    mServer.setAuth(KLDAPCore::LdapServer::Anonymous);
    if (tmp == "Simple"_L1) {
        mServer.setAuth(KLDAPCore::LdapServer::Simple);
    } else if (tmp == "SASL"_L1) {
        mServer.setAuth(KLDAPCore::LdapServer::SASL);
    }

    mServer.setMech(mConfig.readEntry(prefix + u"Mech%1"_s.arg(mServerIndex), QString()));
    mServer.setFilter(mConfig.readEntry(prefix + u"UserFilter%1"_s.arg(mServerIndex), QString()));
    mServer.setCompletionWeight(mConfig.readEntry(prefix + u"CompletionWeight%1"_s.arg(mServerIndex), -1));
    mServer.setActivities(mConfig.readEntry(prefix + u"Activities%1"_s.arg(mServerIndex), QStringList()));
    mServer.setEnablePlasmaActivities(mConfig.readEntry(prefix + u"EnabledActivities%1"_s.arg(mServerIndex), false));

    const QString pwdBindBNEntry = prefix + u"PwdBind%1"_s.arg(mServerIndex);

    auto readJob = new ReadPasswordJob(u"ldapclient"_s, this);
    connect(readJob, &Job::finished, this, [this, pwdBindBNEntry](QKeychain::Job *baseJob) {
        auto job = qobject_cast<ReadPasswordJob *>(baseJob);
        Q_ASSERT(job);
        if (!job->error()) {
            mServer.setPassword(job->textData());
        } else {
            qCWarning(LDAP_CORE_LOG) << "We have an error during reading password " << job->errorString() << " password key " << pwdBindBNEntry;
        }
        readLdapClientConfigFinished();
    });
    readJob->setKey(pwdBindBNEntry);
    readJob->start();
}

#include "moc_ldapclientsearchconfigreadconfigjob.cpp"
