/*
 * SPDX-FileCopyrightText: 2013-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldapwidgets_export.h"

#include <QObject>
#include <memory>
class KConfig;

namespace KLDAPWidgets
{
class LdapClient;
/**
 * @brief The LdapClientSearchConfig class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAPWIDGETS_EXPORT LdapClientSearchConfig : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfig(QObject *parent = nullptr);
    ~LdapClientSearchConfig() override;

    /**
     * Returns the global config object, which stores the LdapClient configurations.
     */
    static KConfig *config();

private:
    //@cond PRIVATE
    class LdapClientSearchConfigPrivate;
    std::unique_ptr<LdapClientSearchConfigPrivate> const d;
};
}
