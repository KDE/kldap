// SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once
#include "kldap_core_export.h"

#include <QSortFilterProxyModel>

namespace KLDAPCore
{
class LdapActivitiesAbstract;
class KLDAP_CORE_EXPORT LdapSortProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    explicit LdapSortProxyModel(QObject *parent);
    ~LdapSortProxyModel() override;

    [[nodiscard]] LdapActivitiesAbstract *ldapActivitiesAbstract() const;
    void setLdapActivitiesAbstract(LdapActivitiesAbstract *newldapActivitiesAbstract);

protected:
    [[nodiscard]] bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;

private:
    LdapActivitiesAbstract *mLdapActivitiesAbstract = nullptr;
};
}
