/*
 * SPDX-FileCopyrightText: 2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPWIDGETITEMREADCONFIGSERVERJOB_H
#define LDAPWIDGETITEMREADCONFIGSERVERJOB_H

#include <QObject>
namespace KLDAP {
class LdapWidgetItem;
class LdapWidgetItemReadConfigServerJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapWidgetItemReadConfigServerJob(QObject *parent = nullptr);
    ~LdapWidgetItemReadConfigServerJob() override;

    LdapWidgetItem *ldapWidgetItem() const;
    void setLdapWidgetItem(LdapWidgetItem *ldapWidgetItem);

private:
    LdapWidgetItem *mLdapWidgetItem = nullptr;
};
}

#endif // LDAPWIDGETITEMREADCONFIGSERVERJOB_H
