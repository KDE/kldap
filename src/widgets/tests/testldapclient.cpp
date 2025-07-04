/* This file is part of the KDE project
   SPDX-FileCopyrightText: 2005 David Faure <faure@kde.org>

   SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "testldapclient.h"

#include <QDebug>

#include <KLDAPCore/LdapObject>

#include <QEventLoop>

#include <QApplication>
#include <QCommandLineParser>
#include <QStandardPaths>
#include <cstdlib>
using namespace Qt::Literals::StringLiterals;
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QStandardPaths::setTestModeEnabled(true);
    QCommandLineParser parser;
    parser.addVersionOption();
    parser.addHelpOption();
    parser.process(app);

    TestLDAPClient test;
    test.setup();
    test.runAll();
    test.cleanup();
    qDebug() << "All tests OK.";
    return 0;
}

TestLDAPClient::TestLDAPClient() = default;

void TestLDAPClient::setup()
{
}

void TestLDAPClient::runAll()
{
    testIntevation();
}

bool TestLDAPClient::check(const QString &txt, QString a, QString b)
{
    if (a.isEmpty()) {
        a.clear();
    }

    if (b.isEmpty()) {
        b.clear();
    }

    if (a == b) {
        qDebug() << txt << " : checking '" << a << "' against expected value '" << b << "'..."
                 << "ok";
    } else {
        qDebug() << txt << " : checking '" << a << "' against expected value '" << b << "'..."
                 << "KO !";
        cleanup();
        exit(1);
    }

    return true;
}

void TestLDAPClient::cleanup()
{
    mClient = nullptr;
}

void TestLDAPClient::testIntevation()
{
    qDebug();
    mClient = new KLDAPCore::LdapClient(0, this);

#if 0
    mClient->setHost("ca.intevation.de");
    mClient->setPort("389");
    mClient->setBase("o=Intevation GmbH,c=de");
#endif

    // Same list as in kaddressbook's ldapsearchdialog
    QStringList attrs;
    attrs << u"l"_s << u"Company"_s << QStringLiteral("co") << QStringLiteral("department") << QStringLiteral("description") << u"mail"_s
          << u"facsimileTelephoneNumber"_s << QStringLiteral("cn") << QStringLiteral("homePhone") << u"mobile"_s << u"o"_s << QStringLiteral("pager")
          << QStringLiteral("postalAddress") << QStringLiteral("st") << u"street"_s << u"title"_s << QStringLiteral("uid") << QStringLiteral("telephoneNumber")
          << QStringLiteral("postalCode") << u"objectClass"_s;
    // the list from ldapclient.cpp
    // attrs << "cn" << "mail" << "givenname" << "sn" << "objectClass";
    mClient->setAttributes(attrs);

    // Taken from LdapSearch
    /*
      QString mSearchText = QString::fromUtf8( "Till" );
      QString filter = QString( "&(|(objectclass=person)(objectclass=groupOfNames)(mail=*))"
                                "(|(cn=%1*)(mail=%2*)(givenName=%3*)(sn=%4*))" )
                       .arg( mSearchText ).arg( mSearchText ).arg( mSearchText ).arg( mSearchText );
     */

    // For some reason a fromUtf8 broke the search for me (no results).
    // But this certainly looks fishy, it might break on non-utf8 systems.
    QString filter = QStringLiteral(
        "&(|(objectclass=person)(objectclass=groupofnames)(mail=*))"
        "(|(cn=*Ägypten MDK*)(sn=*Ägypten MDK*))");

    connect(mClient, &KLDAPCore::LdapClient::result, this, &TestLDAPClient::slotLDAPResult);
    connect(mClient, &KLDAPCore::LdapClient::done, this, &TestLDAPClient::slotLDAPDone);
    connect(mClient, &KLDAPCore::LdapClient::error, this, &TestLDAPClient::slotLDAPError);
    mClient->startQuery(filter);

    QEventLoop eventLoop;
    connect(this, &TestLDAPClient::leaveModality, &eventLoop, &QEventLoop::quit);
    eventLoop.exec(QEventLoop::ExcludeUserInputEvents);

    delete mClient;
    mClient = nullptr;
}

// from kaddressbook... ugly though...
static QString asUtf8(const QByteArray &val)
{
    if (val.isEmpty()) {
        return {};
    }

    const char *data = val.data();

    // QString::fromUtf8() bug workaround
    if (data[val.size() - 1] == '\0') {
        return QString::fromUtf8(data, val.size() - 1);
    } else {
        return QString::fromUtf8(data, val.size());
    }
}

static QString join(const KLDAPCore::LdapAttrValue &lst, const QString &sep)
{
    QString res;
    bool already = false;
    for (KLDAPCore::LdapAttrValue::ConstIterator it = lst.begin(); it != lst.end(); ++it) {
        if (already) {
            res += sep;
        }

        already = true;
        res += asUtf8(*it);
    }

    return res;
}

void TestLDAPClient::slotLDAPResult(const KLDAPCore::LdapClient &, const KLDAPCore::LdapObject &obj)
{
    QString cn = join(obj.attributes()[u"cn"_s], u", "_s);
    qDebug() << " cn:" << cn;
    Q_ASSERT(!obj.attributes()[u"mail"_s].isEmpty());
    QString mail = join(obj.attributes()[u"mail"_s], u", "_s);
    qDebug() << " mail:" << mail;
    Q_ASSERT(mail.contains(u'@'));
}

void TestLDAPClient::slotLDAPError(const QString &err)
{
    qDebug() << err;
    ::exit(1);
}

void TestLDAPClient::slotLDAPDone()
{
    qDebug();
    Q_EMIT leaveModality();
}

#include "moc_testldapclient.cpp"
