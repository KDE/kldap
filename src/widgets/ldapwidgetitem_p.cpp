/*
 * SPDX-FileCopyrightText: 2020-2023 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapwidgetitem_p.h"
using namespace KLDAP;

LdapWidgetItem::LdapWidgetItem(QListWidget *parent, bool isActive)
    : QListWidgetItem(parent, QListWidgetItem::UserType)
    , mIsActive(isActive)
{
    setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsUserCheckable);
    setCheckState(isActive ? Qt::Checked : Qt::Unchecked);
}

void LdapWidgetItem::setServer(const KLDAP::LdapServer &server)
{
    mServer = server;
    setText(mServer.host());
}

const KLDAP::LdapServer &LdapWidgetItem::server() const
{
    return mServer;
}

void LdapWidgetItem::setIsActive(bool isActive)
{
    mIsActive = isActive;
}

bool LdapWidgetItem::isActive() const
{
    return mIsActive;
}
