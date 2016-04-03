/*
  Copyright (c) 2004-2007 Szombathelyi György <gyurco@freemail.hu>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
  AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
  AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
    virtual ~LDAPProtocol();

    virtual void setHost(const QString &host, quint16 port,
                         const QString &user, const QString &pass) Q_DECL_OVERRIDE;

    void openConnection() Q_DECL_OVERRIDE;
    void closeConnection() Q_DECL_OVERRIDE;

    void get(const QUrl &url) Q_DECL_OVERRIDE;
    void stat(const QUrl &url) Q_DECL_OVERRIDE;
    void listDir(const QUrl &url) Q_DECL_OVERRIDE;
    void del(const QUrl &url, bool isfile) Q_DECL_OVERRIDE;
    void put(const QUrl &url, int permissions, KIO::JobFlags flags) Q_DECL_OVERRIDE;

private:

    KLDAP::LdapConnection mConn;
    KLDAP::LdapOperation mOp;
    KLDAP::LdapServer mServer;
    bool mConnected;

    void controlsFromMetaData(KLDAP::LdapControls &serverctrls,
                              KLDAP::LdapControls &clientctrls);
    void LDAPEntry2UDSEntry(const KLDAP::LdapDN &dn, KIO::UDSEntry &entry,
                            const KLDAP::LdapUrl &usrc, bool dir = false);
    int asyncSearch(KLDAP::LdapUrl &usrc, const QByteArray &cookie = "");

    void LDAPErr(int err = KLDAP_SUCCESS);
    void changeCheck(const KLDAP::LdapUrl &url);
};

#endif
