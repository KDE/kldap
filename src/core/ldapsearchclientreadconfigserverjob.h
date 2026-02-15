/*
 * SPDX-FileCopyrightText: 2020-2026 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldap_core_export.h"
#include <KConfigGroup>
#include <QObject>
namespace KLDAPCore
{
class LdapServer;
class LdapClient;
/*!
 * \class KLDAPCore::LdapSearchClientReadConfigServerJob
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapSearchClientReadConfigServerJob
 *
 * \brief The LdapSearchClientReadConfigServerJob class
 */
class KLDAP_CORE_EXPORT LdapSearchClientReadConfigServerJob : public QObject
{
    Q_OBJECT
public:
    /*!
     * Constructs a LdapSearchClientReadConfigServerJob object.
     * \param parent the parent QObject
     */
    explicit LdapSearchClientReadConfigServerJob(QObject *parent = nullptr);

    /*!
     * Destroys the LdapSearchClientReadConfigServerJob object.
     */
    ~LdapSearchClientReadConfigServerJob() override;

    /*!
     * Starts the job.
     */
    void start();

    /*!
     * Returns whether the job can be started.
     * \return true if the job can be started
     */
    [[nodiscard]] bool canStart() const;

    /*!
     * Returns the current server index.
     * \return the current index
     */
    [[nodiscard]] int currentIndex() const;

    /*!
     * Sets the current server index.
     * \param currentIndex the index to set
     */
    void setCurrentIndex(int currentIndex);

    /*!
     * Returns whether the job is active.
     * \return true if the job is active
     */
    [[nodiscard]] bool active() const;

    /*!
     * Sets whether the job is active.
     * \param active true to activate the job
     */
    void setActive(bool active);

    /*!
     * Returns the configuration group.
     * \return the KConfigGroup
     */
    [[nodiscard]] KConfigGroup config() const;

    /*!
     * Sets the configuration group.
     * \param config the KConfigGroup to set
     */
    void setConfig(const KConfigGroup &config);

    /*!
     * Returns the LDAP client.
     * \return the LdapClient object
     */
    [[nodiscard]] LdapClient *ldapClient() const;

    /*!
     * Sets the LDAP client.
     * \param ldapClient the LdapClient to set
     */
    void setLdapClient(LdapClient *ldapClient);

private:
    KLDAP_CORE_NO_EXPORT void slotConfigLoaded(const KLDAPCore::LdapServer &server);
    LdapClient *mLdapClient = nullptr;
    KConfigGroup mConfig;
    int mCurrentIndex = -1;
    bool mActive = false;
};
}
