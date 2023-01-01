/*
 * SPDX-FileCopyrightText: 2020-2023 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfigreadconfigjob.h"
#include "ldapclient_debug.h"

#include <KConfig>
#include <KLocalizedString>
#include <kldap/ldapdn.h>
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <qt5keychain/keychain.h>
#else
#include <qt6keychain/keychain.h>
#endif
using namespace QKeychain;

using namespace KLDAP;
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
        mServer.setBaseDn(KLDAP::LdapDN(base));
    }

    const QString user = mConfig.readEntry(prefix + QStringLiteral("User%1").arg(mServerIndex), QString()).trimmed();
    if (!user.isEmpty()) {
        mServer.setUser(user);
    }

    const QString bindDN = mConfig.readEntry(prefix + QStringLiteral("Bind%1").arg(mServerIndex), QString()).trimmed();
    if (!bindDN.isEmpty()) {
        mServer.setBindDn(bindDN);
    }
#if 0 // Port
    const QString pwdBindBNEntry = prefix + QStringLiteral("PwdBind%1").arg(mServerIndex);
    QString pwdBindDN = mConfig.readEntry(pwdBindBNEntry, QString());
    if (!pwdBindDN.isEmpty()) {
        if (d->askWallet && KMessageBox::Yes == KMessageBox::questionYesNo(nullptr, i18n("LDAP password is stored as clear text, do you want to store it in kwallet?"),
                                                                           i18n("Store clear text password in Wallet"),
                                                                           KStandardGuiItem::yes(),
                                                                           KStandardGuiItem::no(),
                                                                           QStringLiteral("DoAskToStoreToWallet"))) {
            d->wallet = KWallet::Wallet::openWallet(KWallet::Wallet::LocalWallet(), 0);
            if (d->wallet) {
                connect(d->wallet, &KWallet::Wallet::walletClosed, this, &LdapClientSearchConfig::slotWalletClosed);
                d->useWallet = true;
                if (!d->wallet->hasFolder(QStringLiteral("ldapclient"))) {
                    d->wallet->createFolder(QStringLiteral("ldapclient"));
                }
                d->wallet->setFolder(QStringLiteral("ldapclient"));
                d->wallet->writePassword(pwdBindBNEntry, pwdBindDN);
                mConfig.deleteEntry(pwdBindBNEntry);
                mConfig.sync();
            }
        }
        mServer.setPassword(pwdBindDN);
    } else if (d->askWallet) { //Look at in Wallet
        //Move as async here.
        d->wallet = KWallet::Wallet::openWallet(KWallet::Wallet::LocalWallet(), 0);
        if (d->wallet) {
            d->useWallet = true;
            if (!d->wallet->setFolder(QStringLiteral("ldapclient"))) {
                d->wallet->createFolder(QStringLiteral("ldapclient"));
                d->wallet->setFolder(QStringLiteral("ldapclient"));
            }
            d->wallet->readPassword(pwdBindBNEntry, pwdBindDN);
            if (!pwdBindDN.isEmpty()) {
                mServer.setPassword(pwdBindDN);
            }
        } else {
            d->useWallet = false;
        }
    }
#endif
    mServer.setTimeLimit(mConfig.readEntry(prefix + QStringLiteral("TimeLimit%1").arg(mServerIndex), 0));
    mServer.setSizeLimit(mConfig.readEntry(prefix + QStringLiteral("SizeLimit%1").arg(mServerIndex), 0));
    mServer.setPageSize(mConfig.readEntry(prefix + QStringLiteral("PageSize%1").arg(mServerIndex), 0));
    mServer.setVersion(mConfig.readEntry(prefix + QStringLiteral("Version%1").arg(mServerIndex), 3));

    QString tmp = mConfig.readEntry(prefix + QStringLiteral("Security%1").arg(mServerIndex), QStringLiteral("None"));
    mServer.setSecurity(KLDAP::LdapServer::None);
    if (tmp == QLatin1String("SSL")) {
        mServer.setSecurity(KLDAP::LdapServer::SSL);
    } else if (tmp == QLatin1String("TLS")) {
        mServer.setSecurity(KLDAP::LdapServer::TLS);
    }

    tmp = mConfig.readEntry(prefix + QStringLiteral("Auth%1").arg(mServerIndex), QStringLiteral("Anonymous"));
    mServer.setAuth(KLDAP::LdapServer::Anonymous);
    if (tmp == QLatin1String("Simple")) {
        mServer.setAuth(KLDAP::LdapServer::Simple);
    } else if (tmp == QLatin1String("SASL")) {
        mServer.setAuth(KLDAP::LdapServer::SASL);
    }

    mServer.setMech(mConfig.readEntry(prefix + QStringLiteral("Mech%1").arg(mServerIndex), QString()));
    mServer.setFilter(mConfig.readEntry(prefix + QStringLiteral("UserFilter%1").arg(mServerIndex), QString()));
    mServer.setCompletionWeight(mConfig.readEntry(prefix + QStringLiteral("CompletionWeight%1").arg(mServerIndex), -1));

    const QString pwdBindBNEntry = prefix + QStringLiteral("PwdBind%1").arg(mServerIndex);

    auto readJob = new ReadPasswordJob(QStringLiteral("ldapclient"), this);
    connect(readJob, &Job::finished, this, &LdapClientSearchConfigReadConfigJob::readLdapPasswordFinished);
    readJob->setKey(pwdBindBNEntry);
    readJob->start();
}

void LdapClientSearchConfigReadConfigJob::readLdapPasswordFinished(QKeychain::Job *baseJob)
{
    auto job = qobject_cast<ReadPasswordJob *>(baseJob);
    Q_ASSERT(job);
    if (!job->error()) {
        mServer.setPassword(job->textData());
    } else {
        qCWarning(LDAPCLIENT_LOG) << "We have an error during reading password " << job->errorString();
    }
    readLdapClientConfigFinished();
}
