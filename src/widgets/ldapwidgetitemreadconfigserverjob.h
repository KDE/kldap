/*
 * SPDX-FileCopyrightText: 2020-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <KConfigGroup>
#include <QObject>
namespace KLDAPCore
{
class LdapServer;
}
namespace KLDAPWidgets
{
class LdapWidgetItem;
class LdapWidgetItemReadConfigServerJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapWidgetItemReadConfigServerJob(QObject *parent = nullptr);
    ~LdapWidgetItemReadConfigServerJob() override;

    void start();

    LdapWidgetItem *ldapWidgetItem() const;
    void setLdapWidgetItem(LdapWidgetItem *ldapWidgetItem);

    [[nodiscard]] int currentIndex() const;
    void setCurrentIndex(int currentIndex);

    [[nodiscard]] bool active() const;
    void setActive(bool active);

    [[nodiscard]] KConfigGroup config() const;
    void setConfig(const KConfigGroup &config);

private:
    void slotConfigLoaded(const KLDAPCore::LdapServer &server);
    LdapWidgetItem *mLdapWidgetItem = nullptr;
    KConfigGroup mConfig;
    int mCurrentIndex = -1;
    bool mActive = false;
};
}
