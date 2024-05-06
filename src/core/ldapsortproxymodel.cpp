// SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "ldapsortproxymodel.h"
#include "ldapactivitiesabstract.h"
#include "ldapmodel.h"
using namespace KLDAPCore;
LdapSortProxyModel::LdapSortProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent)
{
}

LdapSortProxyModel::~LdapSortProxyModel() = default;

bool LdapSortProxyModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    if (mLdapActivitiesAbstract) {
        const auto activities = sourceModel()->index(source_row, 0).data(LdapModel::Activities).toStringList();
        return mLdapActivitiesAbstract->filterAcceptsRow(activities);
    }
    return QSortFilterProxyModel::filterAcceptsRow(source_row, source_parent);
}

LdapActivitiesAbstract *LdapSortProxyModel::ldapActivitiesAbstract() const
{
    return mLdapActivitiesAbstract;
}

void LdapSortProxyModel::setLdapActivitiesAbstract(LdapActivitiesAbstract *newIdentityActivitiesAbstract)
{
    if (mLdapActivitiesAbstract != newIdentityActivitiesAbstract) {
        mLdapActivitiesAbstract = newIdentityActivitiesAbstract;
        connect(mLdapActivitiesAbstract, &LdapActivitiesAbstract::activitiesChanged, this, &LdapSortProxyModel::invalidateFilter);
        invalidateFilter();
    }
}

#include "moc_ldapsortproxymodel.cpp"
