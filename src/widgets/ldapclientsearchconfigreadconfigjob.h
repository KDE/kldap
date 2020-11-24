/*
 * SPDX-FileCopyrightText: 2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPCLIENTSEARCHCONFIGREADCONFIGJOB_H
#define LDAPCLIENTSEARCHCONFIGREADCONFIGJOB_H
#include <QObject>
#include <KConfigGroup>

#include <KLDAP/LdapServer>
namespace KLDAP {
class LdapClientSearchConfigReadConfigJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfigReadConfigJob(QObject *parent = nullptr);
    ~LdapClientSearchConfigReadConfigJob() override;

    Q_REQUIRED_RESULT bool canStart() const;
    void start();

    Q_REQUIRED_RESULT bool active() const;
    void setActive(bool newActive);

    Q_REQUIRED_RESULT int serverIndex() const;
    void setServerIndex(int newServerIndex);

    Q_REQUIRED_RESULT KConfigGroup config() const;
    void setConfig(const KConfigGroup &newConfig);

Q_SIGNALS:
    void configLoaded(const KLDAP::LdapServer &server);

private:
    void searchLdapClientConfigFinished();
    void readConfig();
    int mServerIndex = -1;
    KConfigGroup mConfig;
    bool mActive = false;
    KLDAP::LdapServer mServer;
};

}
#endif // LDAPCLIENTSEARCHCONFIGREADCONFIGJOB_H
