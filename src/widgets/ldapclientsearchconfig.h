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
     * Reads the LDAP @p server settings from the given config @p group for the
     * given LDAP @p clientNumber.
     *
     * @param active Defines whether the active settings shall be read.
     */
    void readConfig(KLDAP::LdapServer &server, KConfigGroup &group, int clientNumber, bool active);

    /**
     * Writes the LDAP @p server settings to the given config @p group for the
     * given LDAP @p clientNumber.
     *
     * @param active Defines whether the active settings shall be written.
     */
    void writeConfig(const KLDAP::LdapServer &server, KConfigGroup &group, int clientNumber, bool active);

    /**
     * Should LdapClientSearchConfig ask, if it should use the KWallet to store passwords
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
