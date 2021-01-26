/*
 * SPDX-FileCopyrightText: 2013-2021 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfig.h"
#include "ldapclient_debug.h"
#include <kldap/ldapserver.h>

#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <qt5keychain/keychain.h>
using namespace QKeychain;
using namespace KLDAP;

class Q_DECL_HIDDEN LdapClientSearchConfig::Private
{
public:
    Private()
    {
    }

    ~Private()
    {
    }
};

Q_GLOBAL_STATIC_WITH_ARGS(KConfig, s_config, (QLatin1String("kabldaprc"), KConfig::NoGlobals))

KConfig *LdapClientSearchConfig::config()
{
    return s_config;
}

LdapClientSearchConfig::LdapClientSearchConfig(QObject *parent)
    : QObject(parent)
    , d(new LdapClientSearchConfig::Private())
{
}

LdapClientSearchConfig::~LdapClientSearchConfig()
{
    delete d;
}
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
