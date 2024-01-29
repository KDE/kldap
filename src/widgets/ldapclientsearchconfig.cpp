/*
 * SPDX-FileCopyrightText: 2013-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfig.h"
#include <kldapcore/ldapserver.h>

#include <KConfig>
#include <qt6keychain/keychain.h>
using namespace QKeychain;
using namespace KLDAPWidgets;

class Q_DECL_HIDDEN LdapClientSearchConfig::LdapClientSearchConfigPrivate
{
public:
    LdapClientSearchConfigPrivate() = default;

    ~LdapClientSearchConfigPrivate() = default;
};

Q_GLOBAL_STATIC_WITH_ARGS(KConfig, s_config, (QLatin1StringView("kabldaprc"), KConfig::NoGlobals))

KConfig *LdapClientSearchConfig::config()
{
    return s_config;
}

LdapClientSearchConfig::LdapClientSearchConfig(QObject *parent)
    : QObject(parent)
    , d(new LdapClientSearchConfig::LdapClientSearchConfigPrivate())
{
}

LdapClientSearchConfig::~LdapClientSearchConfig() = default;

#if 0 // Port it
void LdapClientSearchConfig::clearWalletPassword()
{
    if (!d->wallet) {
        d->wallet = KWallet::Wallet::openWallet(KWallet::Wallet::LocalWallet(), 0);
    }
    if (d->wallet) {
        d->useWallet = true;
        if (d->wallet->hasFolder(QStringLiteral("ldapclient"))) {
            //Recreate it.
            d->wallet->removeFolder(QStringLiteral("ldapclient"));
            d->wallet->createFolder(QStringLiteral("ldapclient"));
            d->wallet->setFolder(QStringLiteral("ldapclient"));
        }
    }
}
#endif

#include "moc_ldapclientsearchconfig.cpp"
