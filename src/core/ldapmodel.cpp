/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapmodel.h"
#include "ldapserver.h"
using namespace KLDAPCore;
LdapModel::LdapModel(QObject *parent)
    : QAbstractListModel{parent}
{
}

LdapModel::~LdapModel() = default;

QVariant LdapModel::data(const QModelIndex &index, int role) const
{
    return {};
}

int LdapModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    return mLdapServer.count();
}

int LdapModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    constexpr int nbCol = static_cast<int>(LdapRoles::LastColumn) + 1;
    return nbCol;
}

QVariant LdapModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    // TODO
    return {};
}

#include "moc_ldapmodel.cpp"
