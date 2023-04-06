/*
 * SPDX-FileCopyrightText: 2020-2023 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <QListWidget>
#include <kldap/ldapserver.h>
namespace KLDAPWidgets
{
class LdapWidgetItem : public QListWidgetItem
{
public:
    explicit LdapWidgetItem(QListWidget *parent, bool isActive = false);

    void setServer(const KLDAPCore::LdapServer &server);

    const KLDAPCore::LdapServer &server() const;

    void setIsActive(bool isActive);

    Q_REQUIRED_RESULT bool isActive() const;

private:
    KLDAPCore::LdapServer mServer;
    bool mIsActive = false;
};
}
