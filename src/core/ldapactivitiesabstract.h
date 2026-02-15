// SPDX-FileCopyrightText: 2024-2026 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include "kldap_core_export.h"
#include <QObject>

namespace KLDAPCore
{
/*!
 * \class KLDAPCore::LdapActivitiesAbstract
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapActivitiesAbstract
 *
 * \brief The LdapActivitiesAbstract class
 * \author Laurent Montel <montel@kde.org>
 */
class KLDAP_CORE_EXPORT LdapActivitiesAbstract : public QObject
{
    Q_OBJECT
public:
    /*!
     * Constructs a LdapActivitiesAbstract object.
     * \param parent the parent QObject
     */
    explicit LdapActivitiesAbstract(QObject *parent = nullptr);

    /*!
     * Destroys the LdapActivitiesAbstract object.
     */
    ~LdapActivitiesAbstract() override;

    /*!
     * Returns whether the given list of activities should be accepted by the filter.
     * This is a pure virtual function that must be implemented by subclasses.
     * \param activities the list of activities to filter
     * \return true if the activities should be accepted, false otherwise
     */
    [[nodiscard]] virtual bool filterAcceptsRow(const QStringList &activities) const = 0;

    /*!
     * Returns whether the system has support for activities.
     * This is a pure virtual function that must be implemented by subclasses.
     * \return true if activities are supported, false otherwise
     */
    [[nodiscard]] virtual bool hasActivitySupport() const = 0;

    /*!
     * Returns the current activity.
     * This is a pure virtual function that must be implemented by subclasses.
     * \return the current activity string
     */
    [[nodiscard]] virtual QString currentActivity() const = 0;

Q_SIGNALS:
    /*!
     * Emitted when the activities have changed.
     */
    void activitiesChanged();
};
}
