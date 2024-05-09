/*
 * SPDX-FileCopyrightText: 2013-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfig.h"
using namespace Qt::Literals::StringLiterals;

#include "kldapcore/ldapserver.h"

#include <KConfig>
#include <qt6keychain/keychain.h>
using namespace QKeychain;
using namespace KLDAPCore;

class Q_DECL_HIDDEN LdapClientSearchConfig::LdapClientSearchConfigPrivate
{
public:
    LdapClientSearchConfigPrivate() = default;

    ~LdapClientSearchConfigPrivate() = default;
};

Q_GLOBAL_STATIC_WITH_ARGS(KConfig, s_config, ("kabldaprc"_L1, KConfig::NoGlobals))

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

#include "moc_ldapclientsearchconfig.cpp"
