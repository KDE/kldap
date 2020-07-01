/*
  SPDX-FileCopyrightText: 2004-2007 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: MIT
*/

#ifndef __LDAP_H__
#define __LDAP_H__

#include <kio/slavebase.h>
#include <kio/authinfo.h>

#include <kldap/ldapdefs.h>
#include <kldap/ldapurl.h>
#include <kldap/ldapcontrol.h>
#include <kldap/ldapconnection.h>
#include <kldap/ldapdn.h>
#include <kldap/ldapoperation.h>

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
    int asyncSearch(KLDAP::LdapUrl &usrc, const QByteArray &cookie = "");

    void LDAPErr(int err = KLDAP_SUCCESS);
    void changeCheck(const KLDAP::LdapUrl &url);
};

#endif
