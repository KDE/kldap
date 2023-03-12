/*
  SPDX-FileCopyrightText: 2004-2007 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: MIT
*/

#pragma once

#include <KIO/AuthInfo>
#include <KIO/WorkerBase>

#include <kldap/ldapconnection.h>
#include <kldap/ldapcontrol.h>
#include <kldap/ldapdefs.h>
#include <kldap/ldapdn.h>
#include <kldap/ldapoperation.h>
#include <kldap/ldapurl.h>

class LDAPProtocol : public KIO::WorkerBase
{
public:
    LDAPProtocol(const QByteArray &protocol, const QByteArray &pool, const QByteArray &app);
    ~LDAPProtocol() override;

    void setHost(const QString &host, quint16 port, const QString &user, const QString &pass) override;

    Q_REQUIRED_RESULT KIO::WorkerResult openConnection() override;
    void closeConnection() override;

    KIO::WorkerResult get(const QUrl &url) override;
    KIO::WorkerResult stat(const QUrl &url) override;
    KIO::WorkerResult listDir(const QUrl &url) override;
    KIO::WorkerResult del(const QUrl &url, bool isfile) override;
    KIO::WorkerResult put(const QUrl &url, int permissions, KIO::JobFlags flags) override;

private:
    QByteArray mProtocol;
    KLDAP::LdapConnection mConn;
    KLDAP::LdapOperation mOp;
    KLDAP::LdapServer mServer;
    bool mConnected = false;

    void controlsFromMetaData(KLDAP::LdapControls &serverctrls, KLDAP::LdapControls &clientctrls);
    void LDAPEntry2UDSEntry(const KLDAP::LdapDN &dn, KIO::UDSEntry &entry, const KLDAP::LdapUrl &usrc, bool dir = false);

    KIO::WorkerResult LDAPErr(int err = KLDAP_SUCCESS);
    KIO::WorkerResult changeCheck(const KLDAP::LdapUrl &url);
};
