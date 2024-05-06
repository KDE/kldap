// SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "ldapactivitiesabstract.h"

using namespace KIdentityManagementCore;
LdapActivitiesAbstract::LdapActivitiesAbstract(QObject *parent)
    : QObject{parent}
{
}

LdapActivitiesAbstract::~LdapActivitiesAbstract() = default;

#include "moc_ldapactivitiesabstract.cpp"
