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
    init();
}

LdapModel::~LdapModel() = default;

void LdapModel::init()
{
    // TODO
}

QList<LdapModel::ServerInfo> LdapModel::ldapServerInfo() const
{
    return mLdapServerInfo;
}

void LdapModel::setLdapServerInfo(const QList<ServerInfo> &newLdapServerInfo)
{
    mLdapServerInfo = newLdapServerInfo;
}

QVariant LdapModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return {};
    }
    // TODO
    return {};
}

int LdapModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    return mLdapServerInfo.count();
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
