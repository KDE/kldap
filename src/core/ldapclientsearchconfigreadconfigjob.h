/*
 * SPDX-FileCopyrightText: 2020-2026 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once
#include "kldap_core_export.h"
#include <KConfigGroup>
#include <KLDAPCore/LdapServer>
#include <QObject>
namespace QKeychain
{
class Job;
}
namespace KLDAPCore
{
/*!
 * \class KLDAPCore::LdapClientSearchConfigReadConfigJob
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapClientSearchConfigReadConfigJob
 *
 * \brief The LdapClientSearchConfigReadConfigJob class
 * \author Laurent Montel <montel@kde.org>
 */
class KLDAP_CORE_EXPORT LdapClientSearchConfigReadConfigJob : public QObject
{
    Q_OBJECT
public:
    /*!
     */
    explicit LdapClientSearchConfigReadConfigJob(QObject *parent = nullptr);
    /*!
     */
    ~LdapClientSearchConfigReadConfigJob() override;

    /*!
     */
    [[nodiscard]] bool canStart() const;
    /*!
     */
    void start();

    /*!
     */
    [[nodiscard]] bool active() const;
    /*!
     */
    void setActive(bool newActive);

    /*!
     */
    [[nodiscard]] int serverIndex() const;
    /*!
     */
    void setServerIndex(int newServerIndex);

    /*!
     */
    [[nodiscard]] KConfigGroup config() const;
    /*!
     */
    void setConfig(const KConfigGroup &newConfig);

Q_SIGNALS:
    /*!
     */
    void configLoaded(const KLDAPCore::LdapServer &server);

private:
    KLDAP_CORE_NO_EXPORT void readLdapClientConfigFinished();
    KLDAP_CORE_NO_EXPORT void readConfig();
    int mServerIndex = -1;
    KConfigGroup mConfig;
    bool mActive = false;
    KLDAPCore::LdapServer mServer;
};

}
