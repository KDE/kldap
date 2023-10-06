/*
  SPDX-FileCopyrightText: 2004-2007 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: MIT
*/

#pragma once

#include <KIO/AuthInfo>
#include <KIO/WorkerBase>

#include <kldapcore/ldapconnection.h>
#include <kldapcore/ldapcontrol.h>
#include <kldapcore/ldapdefs.h>
#include <kldapcore/ldapdn.h>
#include <kldapcore/ldapoperation.h>
#include <kldapcore/ldapurl.h>

class LDAPProtocol : public KIO::WorkerBase
{
public:
    LDAPProtocol(const QByteArray &protocol, const QByteArray &pool, const QByteArray &app);
    ~LDAPProtocol() override;

    void setHost(const QString &host, quint16 port, const QString &user, const QString &pass) override;

    [[nodiscard]] KIO::WorkerResult openConnection() override;
    void closeConnection() override;

    KIO::WorkerResult get(const QUrl &url) override;
    KIO::WorkerResult stat(const QUrl &url) override;
    KIO::WorkerResult listDir(const QUrl &url) override;
    KIO::WorkerResult del(const QUrl &url, bool isfile) override;
    KIO::WorkerResult put(const QUrl &url, int permissions, KIO::JobFlags flags) override;

private:
    QByteArray mProtocol;
    KLDAPCore::LdapConnection mConn;
    KLDAPCore::LdapOperation mOp;
    KLDAPCore::LdapServer mServer;
    bool mConnected = false;

    void controlsFromMetaData(KLDAPCore::LdapControls &serverctrls, KLDAPCore::LdapControls &clientctrls);
    void LDAPEntry2UDSEntry(const KLDAPCore::LdapDN &dn, KIO::UDSEntry &entry, const KLDAPCore::LdapUrl &usrc, bool dir = false);

    KIO::WorkerResult LDAPErr(int err = KLDAP_SUCCESS);
    KIO::WorkerResult changeCheck(const KLDAPCore::LdapUrl &url);
};
