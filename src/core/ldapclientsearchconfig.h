/*
 * SPDX-FileCopyrightText: 2013-2025 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldap_core_export.h"

#include <QObject>
#include <memory>
class KConfig;

namespace KLDAPCore
{
/*!
 * \class KLDAPCore::LdapClientSearchConfig
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapClientSearchConfig
 *
 * \brief The LdapClientSearchConfig class
 * \author Laurent Montel <montel@kde.org>
 */
class KLDAP_CORE_EXPORT LdapClientSearchConfig : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfig(QObject *parent = nullptr);
    ~LdapClientSearchConfig() override;

    /*!
     * Returns the global config object, which stores the LdapClient configurations.
     */
    static KConfig *config();

private:
    class LdapClientSearchConfigPrivate;
    std::unique_ptr<LdapClientSearchConfigPrivate> const d;
};
}
