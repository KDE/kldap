// SPDX-FileCopyrightText: 2024-2025 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once
#include "kldap_core_export.h"

#include <QSortFilterProxyModel>

namespace KLDAPCore
{
class LdapActivitiesAbstract;
/*!
 * \class KLDAPCore::LdapSortProxyModel
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapSortProxyModel
 *
 * \brief The LdapSortProxyModel class
 */
class KLDAP_CORE_EXPORT LdapSortProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    /*!
     */
    explicit LdapSortProxyModel(QObject *parent);
    /*!
     */
    ~LdapSortProxyModel() override;

    /*!
     */
    [[nodiscard]] LdapActivitiesAbstract *ldapActivitiesAbstract() const;
    /*!
     */
    void setLdapActivitiesAbstract(LdapActivitiesAbstract *newldapActivitiesAbstract);

    /*!
     */
    [[nodiscard]] bool enablePlasmaActivities() const;
    /*!
     */
    void setEnablePlasmaActivities(bool newEnablePlasmaActivities);

protected:
    [[nodiscard]] bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;
    [[nodiscard]] bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;

private:
    KLDAP_CORE_NO_EXPORT void slotInvalidateFilter();
    LdapActivitiesAbstract *mLdapActivitiesAbstract = nullptr;
    bool mEnablePlasmaActivities = false;
};
}
