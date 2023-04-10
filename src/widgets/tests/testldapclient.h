/* This file is part of the KDE project
   SPDX-FileCopyrightText: 2005 David Faure <faure@kde.org>

   SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include "ldapclient.h"

namespace KLDAPCore
{
class LdapObject;
}
namespace KLDAPWidgets
{
class LdapClient;
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

private:
    void slotLDAPResult(const KLDAPWidgets::LdapClient &, const KLDAPCore::LdapObject &);
    void slotLDAPError(const QString &);
    void slotLDAPDone();
    bool check(const QString &, QString, QString);

    KLDAPWidgets::LdapClient *mClient = nullptr;
};
