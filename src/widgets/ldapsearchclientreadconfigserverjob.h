/*
 * SPDX-FileCopyrightText: 2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPSEARCHCLIENTREADCONFIGSERVERJOB_H
#define LDAPSEARCHCLIENTREADCONFIGSERVERJOB_H

#include <QObject>
#include <KConfigGroup>
namespace KLDAP {
class LdapClient;
class LdapServer;
class LdapSearchClientReadConfigServerJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapSearchClientReadConfigServerJob(QObject *parent = nullptr);
    ~LdapSearchClientReadConfigServerJob() override;

    void start();

    Q_REQUIRED_RESULT int currentIndex() const;
    void setCurrentIndex(int currentIndex);

    Q_REQUIRED_RESULT bool active() const;
    void setActive(bool active);

    Q_REQUIRED_RESULT KConfigGroup config() const;
    void setConfig(const KConfigGroup &config);

    LdapClient *ldapClient() const;
    void setLdapClient(LdapClient *ldapClient);

private:
    void slotConfigLoaded(const KLDAP::LdapServer &server);
    LdapClient *mLdapClient = nullptr;
    KConfigGroup mConfig;
    int mCurrentIndex = -1;
    bool mActive = false;
};
}

#endif // LDAPSEARCHCLIENTREADCONFIGSERVERJOB_H
