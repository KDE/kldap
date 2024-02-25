/*
 * SPDX-FileCopyrightText: 2020-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldapwidgets_export.h"
#include <KConfigGroup>
#include <QObject>
namespace KLDAPCore
{
class LdapServer;
}
namespace KLDAPWidgets
{
class LdapClient;
class KLDAPWIDGETS_EXPORT LdapSearchClientReadConfigServerJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapSearchClientReadConfigServerJob(QObject *parent = nullptr);
    ~LdapSearchClientReadConfigServerJob() override;

    void start();
    [[nodiscard]] bool canStart() const;

    [[nodiscard]] int currentIndex() const;
    void setCurrentIndex(int currentIndex);

    [[nodiscard]] bool active() const;
    void setActive(bool active);

    [[nodiscard]] KConfigGroup config() const;
    void setConfig(const KConfigGroup &config);

    [[nodiscard]] LdapClient *ldapClient() const;
    void setLdapClient(LdapClient *ldapClient);

private:
    KLDAPWIDGETS_NO_EXPORT void slotConfigLoaded(const KLDAPCore::LdapServer &server);
    LdapClient *mLdapClient = nullptr;
    KConfigGroup mConfig;
    int mCurrentIndex = -1;
    bool mActive = false;
};
}
