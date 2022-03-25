/* This file is part of the KDE project
   SPDX-FileCopyrightText: 2005 David Faure <faure@kde.org>

   SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include "widgets/ldapclient.h"

namespace KLDAP
{
class LdapClient;
class LdapObject;
}

class TestLDAPClient : public QObject
{
    Q_OBJECT

public:
    TestLDAPClient();
    void setup();
    void runAll();
    void cleanup();

    // tests
    void testIntevation();

Q_SIGNALS:
    void leaveModality();

private Q_SLOTS:
    void slotLDAPResult(const KLDAP::LdapClient &, const KLDAP::LdapObject &);
    void slotLDAPError(const QString &);
    void slotLDAPDone();

private:
    bool check(const QString &, QString, QString);

    KLDAP::LdapClient *mClient = nullptr;
};
