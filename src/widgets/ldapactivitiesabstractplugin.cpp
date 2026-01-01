/*
  SPDX-FileCopyrightText: 2024-2026 Laurent Montel <montel@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapactivitiesabstractplugin.h"

using namespace KLDAPWidgets;
LdapActivitiesAbstractPlugin::LdapActivitiesAbstractPlugin(QWidget *parent)
    : QWidget{parent}
{
}

LdapActivitiesAbstractPlugin::~LdapActivitiesAbstractPlugin() = default;

#include "moc_ldapactivitiesabstractplugin.cpp"
