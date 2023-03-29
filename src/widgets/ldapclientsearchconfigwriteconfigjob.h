/*
 * SPDX-FileCopyrightText: 2020-2023 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once
#include "kldap_export.h"
#include <KConfigGroup>
#include <KLDAP/LdapServer>
#include <QObject>
namespace QKeychain
{
class Job;
}
namespace KLDAP
{
class KLDAP_EXPORT LdapClientSearchConfigWriteConfigJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfigWriteConfigJob(QObject *parent = nullptr);
    ~LdapClientSearchConfigWriteConfigJob() override;

    Q_REQUIRED_RESULT bool canStart() const;
    void start();

    Q_REQUIRED_RESULT bool active() const;
    void setActive(bool newActive);

    Q_REQUIRED_RESULT int serverIndex() const;
    void setServerIndex(int newServerIndex);

    Q_REQUIRED_RESULT KConfigGroup config() const;
    void setConfig(const KConfigGroup &newConfig);

    Q_REQUIRED_RESULT KLDAP::LdapServer server() const;
    void setServer(const KLDAP::LdapServer &server);

Q_SIGNALS:
    void configSaved();

private:
    KLDAP_NO_EXPORT void writeLdapClientConfigFinished();
    KLDAP_NO_EXPORT void writeConfig();
    int mServerIndex = -1;
    KConfigGroup mConfig;
    bool mActive = false;
    KLDAP::LdapServer mServer;
};

}
