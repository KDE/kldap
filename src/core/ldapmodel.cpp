/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapmodel.h"
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
    // TODO
    return {};
}

int LdapModel::columnCount(const QModelIndex &parent) const
{
    // TODO
    return {};
}

QVariant LdapModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    // TODO
    return {};
}

#include "moc_ldapmodel.cpp"
