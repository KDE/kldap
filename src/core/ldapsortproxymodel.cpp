// SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "ldapsortproxymodel.h"
#include "ldapactivitiesabstract.h"
#include "ldapmodel.h"
using namespace KLDAPCore;
LdapSortProxyModel::LdapSortProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent)
{
    setFilterKeyColumn(LdapModel::Index);
}

LdapSortProxyModel::~LdapSortProxyModel() = default;

bool LdapSortProxyModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    if (mLdapActivitiesAbstract && mEnablePlasmaActivities) {
        const bool enableActivities = sourceModel()->index(source_row, LdapModel::EnabledActivitiesRole).data().toBool();
        if (enableActivities) {
            const auto activities = sourceModel()->index(source_row, 0).data(LdapModel::Activities).toStringList();
            return mLdapActivitiesAbstract->filterAcceptsRow(activities);
        }
    }
    return QSortFilterProxyModel::filterAcceptsRow(source_row, source_parent);
}

bool LdapSortProxyModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    if (!sourceModel()) {
        return false;
    }
    if (source_left.isValid() && source_right.isValid()) {
        const int left = sourceModel()->data(source_left, LdapModel::Index).toInt();
        const int right = sourceModel()->data(source_right, LdapModel::Index).toInt();
        return left < right;
    } else {
        return false;
    }
    return true;
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

bool LdapSortProxyModel::enablePlasmaActivities() const
{
    return mEnablePlasmaActivities;
}

void LdapSortProxyModel::setEnablePlasmaActivities(bool newEnablePlasmaActivities)
{
    if (mEnablePlasmaActivities != newEnablePlasmaActivities) {
        mEnablePlasmaActivities = newEnablePlasmaActivities;
        invalidateFilter();
    }
}

#include "moc_ldapsortproxymodel.cpp"
