// SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include "kldap_core_export.h"
#include <QObject>

namespace KLDAPCore
{
/**
 * @brief The LdapActivitiesAbstract class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAP_CORE_EXPORT LdapActivitiesAbstract : public QObject
{
    Q_OBJECT
public:
    explicit LdapActivitiesAbstract(QObject *parent = nullptr);
    ~LdapActivitiesAbstract() override;

    [[nodiscard]] virtual bool filterAcceptsRow(const QStringList &activities) const = 0;

    [[nodiscard]] virtual bool hasActivitySupport() const = 0;

    [[nodiscard]] virtual QString currentActivity() const = 0;

Q_SIGNALS:
    void activitiesChanged();
};
}
