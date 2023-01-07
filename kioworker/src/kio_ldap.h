/*
  SPDX-FileCopyrightText: 2004-2007 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: MIT
*/

#pragma once

#include <KIO/AuthInfo>
#include <KIO/SlaveBase>

#include <kldap/ldapconnection.h>
#include <kldap/ldapcontrol.h>
#include <kldap/ldapdefs.h>
#include <kldap/ldapdn.h>
#include <kldap/ldapoperation.h>
#include <kldap/ldapurl.h>

class LDAPProtocol : public KIO::SlaveBase
{
public:
    LDAPProtocol(const QByteArray &protocol, const QByteArray &pool, const QByteArray &app);
    ~LDAPProtocol() override;

    void setHost(const QString &host, quint16 port, const QString &user, const QString &pass) override;

    void openConnection() override;
    void closeConnection() override;

    void get(const QUrl &url) override;
    void stat(const QUrl &url) override;
    void listDir(const QUrl &url) override;
    void del(const QUrl &url, bool isfile) override;
    void put(const QUrl &url, int permissions, KIO::JobFlags flags) override;

private:
    KLDAP::LdapConnection mConn;
    KLDAP::LdapOperation mOp;
    KLDAP::LdapServer mServer;
    bool mConnected;

    void controlsFromMetaData(KLDAP::LdapControls &serverctrls, KLDAP::LdapControls &clientctrls);
    void LDAPEntry2UDSEntry(const KLDAP::LdapDN &dn, KIO::UDSEntry &entry, const KLDAP::LdapUrl &usrc, bool dir = false);

    void LDAPErr(int err = KLDAP_SUCCESS);
    void changeCheck(const KLDAP::LdapUrl &url);
};
