/*
 * SPDX-FileCopyrightText: 2020-2021 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPWIDGETITEM_H
#define LDAPWIDGETITEM_H

#include <QListWidget>
#include <kldap/ldapserver.h>
namespace KLDAP
{
class LdapWidgetItem : public QListWidgetItem
{
public:
    explicit LdapWidgetItem(QListWidget *parent, bool isActive = false);

    void setServer(const KLDAP::LdapServer &server);

    const KLDAP::LdapServer &server() const;

    void setIsActive(bool isActive);

    Q_REQUIRED_RESULT bool isActive() const;

private:
    KLDAP::LdapServer mServer;
    bool mIsActive = false;
};
}

#endif // LDAPWIDGETITEM_H
