/*
 * SPDX-FileCopyrightText: 2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPWIDGETITEMREADCONFIGSERVERJOB_H
#define LDAPWIDGETITEMREADCONFIGSERVERJOB_H

#include <QObject>
#include <KConfigGroup>
namespace KLDAP {
class LdapWidgetItem;
class LdapServer;
class LdapWidgetItemReadConfigServerJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapWidgetItemReadConfigServerJob(QObject *parent = nullptr);
    ~LdapWidgetItemReadConfigServerJob() override;

    void start();

    LdapWidgetItem *ldapWidgetItem() const;
    void setLdapWidgetItem(LdapWidgetItem *ldapWidgetItem);

    Q_REQUIRED_RESULT int currentIndex() const;
    void setCurrentIndex(int currentIndex);

    Q_REQUIRED_RESULT bool active() const;
    void setActive(bool active);

    Q_REQUIRED_RESULT KConfigGroup config() const;
    void setConfig(const KConfigGroup &config);

private:
    void slotConfigLoaded(const KLDAP::LdapServer &server);
    LdapWidgetItem *mLdapWidgetItem = nullptr;
    KConfigGroup mConfig;
    int mCurrentIndex = -1;
    bool mActive = false;
};
}

#endif // LDAPWIDGETITEMREADCONFIGSERVERJOB_H
