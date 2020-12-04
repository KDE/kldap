/*
 * SPDX-FileCopyrightText: 2013-2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPCLIENTSEARCHCONFIG_H
#define LDAPCLIENTSEARCHCONFIG_H

#include "kldap_export.h"

#include <QObject>

class KConfigGroup;
class KConfig;

namespace KLDAP {
class LdapServer;
class LdapClient;
/**
 * @brief The LdapClientSearchConfig class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAP_EXPORT LdapClientSearchConfig : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfig(QObject *parent = nullptr);
    ~LdapClientSearchConfig();

    /**
     * Returns the global config object, which stores the LdapClient configurations.
     */
    static KConfig *config();

    /**
     * Should LdapClientSearchConfig ask, if it should use the Wallet to store passwords
     */
    void askForWallet(bool askForWallet);

    void clearWalletPassword();
private Q_SLOTS:
    void slotWalletClosed();

private:
    //@cond PRIVATE
    class Private;
    Private *const d;
};
}

#endif // LDAPCLIENTSEARCHCONFIG_H
