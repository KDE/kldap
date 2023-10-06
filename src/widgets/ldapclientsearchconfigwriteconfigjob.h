/*
 * SPDX-FileCopyrightText: 2020-2023 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once
#include "kldapwidgets_export.h"
#include <KConfigGroup>
#include <KLDAPCore/LdapServer>
#include <QObject>
namespace QKeychain
{
class Job;
}
namespace KLDAPWidgets
{
class KLDAPWIDGETS_EXPORT LdapClientSearchConfigWriteConfigJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfigWriteConfigJob(QObject *parent = nullptr);
    ~LdapClientSearchConfigWriteConfigJob() override;

    [[nodiscard]] bool canStart() const;
    void start();

    [[nodiscard]] bool active() const;
    void setActive(bool newActive);

    [[nodiscard]] int serverIndex() const;
    void setServerIndex(int newServerIndex);

    [[nodiscard]] KConfigGroup config() const;
    void setConfig(const KConfigGroup &newConfig);

    [[nodiscard]] KLDAPCore::LdapServer server() const;
    void setServer(const KLDAPCore::LdapServer &server);

Q_SIGNALS:
    void configSaved();

private:
    KLDAPWIDGETS_NO_EXPORT void writeLdapClientConfigFinished();
    KLDAPWIDGETS_NO_EXPORT void writeConfig();
    int mServerIndex = -1;
    KConfigGroup mConfig;
    bool mActive = false;
    KLDAPCore::LdapServer mServer;
};

}
