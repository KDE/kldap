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
