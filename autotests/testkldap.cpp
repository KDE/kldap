/*
  This file is part of libkdepim.

  SPDX-FileCopyrightText: 2004 Tobias Koenig <tokoe@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "testkldap.h"

#include "ldif.h"
#include "ldapdn.h"
#include "ldapurl.h"
#include "ldapserver.h"
#include "ldapconnection.h"
#include "ldapoperation.h"
#include "ldapsearch.h"
#include "ber.h"

#include <QDebug>
#include <QTest>
#include <QFile>
QTEST_MAIN(KLdapTest)

KLdapTest::KLdapTest(QObject *parent)
    : QObject(parent)
{
}

void KLdapTest::initTestCase()
{
    /*
      Read in the connection details of an LDAP server to use for testing.
      You should copy the file testurl.txt.tmpl to testurl.txt and specify a url in this file.
      The specified server should not be a production server in case we break anything here.
      You have been warned!
    */
    const QString filename(QStringLiteral("testurl.txt"));
    QFile file(filename);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        stream >> m_url;
        file.close();
    }

    m_search = new LdapSearch;
}

void KLdapTest::testBer()
{
    Ber ber1, ber2, ber3, ber4, ber5, ber6, ber7;
    Ber bber;

    int ainteger;
    QByteArray aoctetString1, aoctetString2, aoctetString3;
    QList<QByteArray> alist1, alist2;

    int binteger;
    QByteArray boctetString1, boctetString2, boctetString3;
    QList<QByteArray> blist1, blist2;

    aoctetString1 = "KDE";
    aoctetString2 = "the";
    aoctetString3 = "next generation";

    alist1.append(aoctetString1);
    alist1.append(aoctetString2);

    alist2.append(aoctetString2);
    alist2.append(aoctetString3);
    alist2.append(aoctetString1);

    ainteger = 23543;

    ber1.printf(QStringLiteral("i"), ainteger);
    ber2.printf(QStringLiteral("o"), &aoctetString1);
    ber3.printf(QStringLiteral("O"), &aoctetString2);
    ber4.printf(QStringLiteral("s"), &aoctetString3);
    ber5.printf(QStringLiteral("{v}"), &alist1);
    ber6.printf(QStringLiteral("{V}"), &alist2);
    ber7.printf(QStringLiteral("oi{v}O"), &aoctetString1, ainteger, &alist2, &aoctetString2);

    //test integer:
    bber = ber1;
    bber.scanf(QStringLiteral("i"), &binteger);
    QCOMPARE(ainteger, binteger);

    //test octet strings:
    bber = ber2;
    bber.scanf(QStringLiteral("o"), &boctetString1);
    QCOMPARE(aoctetString1, boctetString1);
    bber = ber3;
    bber.scanf(QStringLiteral("o"), &boctetString2);
    QCOMPARE(aoctetString2, boctetString2);
    bber = ber4;
    bber.scanf(QStringLiteral("o"), &boctetString3);
    QCOMPARE(aoctetString3, boctetString3);

    //test sequence of octet strings:
    bber = ber5;
    bber.scanf(QStringLiteral("v"), &blist1);
    QCOMPARE(alist1, blist1);

    bber = ber6;
    bber.scanf(QStringLiteral("v"), &blist2);
    QCOMPARE(alist2, blist2);

    //complex tests
    boctetString1 = boctetString2 = boctetString3 = QByteArray();
    binteger = 0;
    blist1.clear();
    blist2.clear();

    bber = ber7;
    bber.scanf(QStringLiteral("oivO"), &boctetString1, &binteger, &blist2, &boctetString2);
    QCOMPARE(aoctetString1, boctetString1);
    QCOMPARE(aoctetString2, boctetString2);
    QCOMPARE(alist2, blist2);
    QCOMPARE(ainteger, binteger);
}

void KLdapTest::cleanupTestCase()
{
    delete m_search;
}

void KLdapTest::testLdapUrl()
{
    // Test LdapUrl using some hardwired values so that we know what to compare to
    LdapUrl url;
    bool critical;

    url.setUrl(QStringLiteral("ldap://cn=manager,dc=kde,dc=org:password@localhost:3999/"
                              "dc=kde,dc=org?cn,mail?sub?(objectClass=*)?x-dir=base"));
    url.parseQuery();

    QCOMPARE(url.userName(), QStringLiteral("cn=manager,dc=kde,dc=org"));
    QCOMPARE(url.password(), QStringLiteral("password"));
    QCOMPARE(url.dn(), LdapDN(QStringLiteral("dc=kde,dc=org")));
    QCOMPARE(url.scope(), LdapUrl::Sub);
    QCOMPARE(url.attributes().at(0), QStringLiteral("cn"));
    QCOMPARE(url.attributes().at(1), QStringLiteral("mail"));
    QCOMPARE(url.filter(), QStringLiteral("(objectClass=*)"));
    QCOMPARE(url.extension(QStringLiteral("x-dir"), critical),
             QStringLiteral("base"));
    QCOMPARE(url.query(), QStringLiteral("?cn,mail?sub??x-dir=base"));
    // For some reason the code removes the filter if it's (objectClass=*)...
    QCOMPARE(url.toString(), QStringLiteral("ldap://cn=manager,dc=kde,dc=org:password@localhost:3999/"
                                            "dc=kde,dc=org??cn,mail?sub??x-dir=base"));

    // Now set a different filter
    url.setFilter(QStringLiteral("(objectclass=person)"));
    QCOMPARE(url.toDisplayString(), QStringLiteral("ldap://cn=manager,dc=kde,dc=org@localhost:3999/"
                                                   "dc=kde,dc=org??cn,mail?sub?%28objectclass%3Dperson%29?x-dir=base"));
    QCOMPARE(url.filter(), QStringLiteral("(objectclass=person)"));

    // And now a filter with non-ascii letters
    url.setFilter(QStringLiteral("(givenName=Valérie *)"));
    QCOMPARE(url.toDisplayString(), QString::fromUtf8("ldap://cn=manager,dc=kde,dc=org@localhost:3999/"
                                                      "dc=kde,dc=org??cn,mail?sub?%28givenName%3DValérie %2A%29?x-dir=base"));
    QCOMPARE(url.filter(), QStringLiteral("(givenName=Valérie *)"));

    // Test roundtrip via QUrl, as happens when sending it to kio_ldap
    const QUrl qurl(url);
    QCOMPARE(qurl.toDisplayString(), url.toDisplayString());

    const LdapUrl kiourl(qurl);
    QCOMPARE(kiourl.toString(), url.toString());
    QCOMPARE(kiourl.toDisplayString(), url.toDisplayString());
    QCOMPARE(kiourl.filter(), QStringLiteral("(givenName=Valérie *)"));
}

void KLdapTest::testLdapConnection()
{
    // Try to connect using an LdapUrl (read in from testurl.txt).
    LdapUrl url;
    url.setUrl(m_url);

    LdapConnection conn;
    conn.setUrl(url);
    int ret;
    if ((ret = conn.connect())) {
        qDebug() << "Could not connect to LDAP server. Error was:" << conn.connectionError();
    }
    QCOMPARE(ret, 0);

    LdapOperation op(conn);
    // Now attempt to bind
    if ((ret = op.bind_s())) {
        qDebug() << "Could not bind to server. Error was:" << conn.ldapErrorString();
    }
    QEXPECT_FAIL("", "Will fail since no server is available for testing", Abort);
    QCOMPARE(ret, 0);
}

void KLdapTest::testLdapSearch()
{
    // Lets try a search using the specified url
    LdapUrl url;
    url.setUrl(m_url);
    url.parseQuery();
    connect(m_search, &LdapSearch::result,
            this, &KLdapTest::searchResult);
    connect(m_search, &LdapSearch::data,
            this, &KLdapTest::searchData);
    const bool success = m_search->search(url);
    QCoreApplication::processEvents();

    QEXPECT_FAIL("", "Will fail since no server is available for testing", Abort);
    QCOMPARE(success, true);

    qDebug() << "Search found" << m_objects.size() << "matching entries";
}

void KLdapTest::searchResult(KLDAP::LdapSearch *search)
{
    qDebug();
    const int err = search->error();
    if (err) {
        qDebug() << "Search returned the following error:" << search->errorString();
    }
    QCOMPARE(err, 0);
}

void KLdapTest::searchData(KLDAP::LdapSearch *search, const KLDAP::LdapObject &obj)
{
    Q_UNUSED(search)
    //qDebug();
    //qDebug() << "Object:";
    //qDebug() << obj.toString();
    m_objects.append(obj);
}

void KLdapTest::testLdapDN()
{
    const QString strDN(QStringLiteral("uid=Test\\+Person+ou=accounts\\,outgoing,dc=kde,dc=org"));
    const LdapDN dn(strDN);
    QCOMPARE(dn.isValid(), true);
    QCOMPARE(dn.rdnString(), QStringLiteral("uid=Test\\+Person+ou=accounts\\,outgoing"));
}

void KLdapTest::testLdapModel()
{
    // Use the user-supplied testing url
    LdapUrl url;
    url.setUrl(m_url);

    // Create a connection to use and bind with it
    LdapConnection conn;
    conn.setUrl(url);
    int ret;
    if ((ret = conn.connect())) {
        qDebug() << "Could not connect to LDAP server. Error was:" << conn.connectionError();
    }
    QCOMPARE(ret, 0);

    LdapOperation op(conn);
    if ((ret = op.bind_s())) {
        qDebug() << "Could not bind to server. Error was:" << conn.ldapErrorString();
    }
    QEXPECT_FAIL("", "Will fail since no server is available for testing", Abort);
    QCOMPARE(ret, 0);

    QCoreApplication::processEvents();
}

/*
  void KLdapTest::testKLdap()
  {
  LdapUrl url;
  bool critical;

  url.setUrl("ldap://cn=manager,dc=kde,dc=org:password@localhost:3999"
             "/dc=kde,dc=org?cn,mail?sub?(objectClass=*)?x-dir=base");
  url.parseQuery();

  QCOMPARE( url.user(), QStringLiteral("cn=manager,dc=kde,dc=org") );
  QCOMPARE( url.password(), QStringLiteral("password") );
  QCOMPARE( url.dn(), QStringLiteral("dc=kde,dc=org") );
  QCOMPARE( url.scope(), LdapUrl::Sub );
  QCOMPARE( url.attributes().at(0), QStringLiteral("cn") );
  QCOMPARE( url.attributes().at(1), QStringLiteral("mail") );
  QCOMPARE( url.filter(), QStringLiteral("(objectClass=*)") );
  QCOMPARE( url.extension(QStringLiteral("x-dir"), critical), QStringLiteral("base") );

  url.setDn("ou=People,dc=kde,dc=org");
  QCOMPARE( url.dn(), QStringLiteral("ou=People,dc=kde,dc=org") );
  url.setDn("/ou=People,dc=kde,dc=org");
  QCOMPARE( url.dn(), QStringLiteral("ou=People,dc=kde,dc=org") );

  LdapServer server;
//  url.setUrl("ldaps://cn=manager,dc=kde,dc=org:passwor@localhost:3999/"
               "dc=kde,dc=org????x-timelimt=5,x-sizelimit=6,x=pagesize=7,binddn=cn=apple,ou=berry");
url.setUrl("ldaps://cn=manager,dc=kde,dc=org:password@localhost:3999/"
           "dc=kde,dc=org??base??x-timelimit=5");
url.parseQuery();
server.setUrl( url );
QCOMPARE( url.query(), QStringLiteral("??base??x-timelimit=5") );
QCOMPARE( url.url(), server.url().url() );

LdapControl c1;
c1.setControl( QStringLiteral("1.2.3.4.5.6"), QByteArray("abcdefg"), true );
//test copy constructor
LdapControl c2(c1);
QCOMPARE( c2.oid(), QStringLiteral("1.2.3.4.5.6") );
QCOMPARE( c2.value(), QByteArray("abcdefg") );
QCOMPARE( c2.critical(), true );
//test assignment operator
LdapControl c3;
c3 = c1;
QCOMPARE( c3.oid(), QStringLiteral("1.2.3.4.5.6") );
QCOMPARE( c3.value(), QByteArray("abcdefg") );
QCOMPARE( c3.critical(), true );
*/
//test Ber functions
/*
  QByteArray left1("bertest"), right1;
  int left2 = 0, right2;
  int left3 = 1, right3;
  int left4 = 2, right4;
  int left5 = 3, right5;
  int left6 = 1, right6;
  QList<QByteArray> left7, right7;
  left7.append( "abcdefghij" );
  left7.append( "123456789" );
  left7.append( "1234\0\0\056789" );

  Ber ber;
  ber.printf("{seeiib}", &left1, left2, left3, left4, left5, left6 );

//  ber.printf("{ioOi{i}}", left3, &left1, &left2, left4, left4 );
Ber ber2 = ber;

unsigned int a;
int b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;
a = ber2.skipTag( b );
qDebug() << "next tag:" << a << "size:" << b;

BerElement *_ber, *_ber2;
_ber = ber_alloc_t( LBER_USE_DER );

ber_len_t bl;
ber_printf( _ber, "{i}", 5 );
qDebug() << "native";
_ber2 = ber_dup( _ber );
a = ber_skip_tag( _ber2, &bl );
qDebug() << "next tag:" << a << "size:" << bl;
//  ber_dump( _ber, 0 );

//  ber2.scanf("{v}", &right5 );

//  ber2.scanf("{inoOi{v}}", &right3, &right1, &right2, &right4, &right5 );

//  QCOMPARE( left1, right1 );
//  QCOMPARE( left2, right2 );
//  QCOMPARE( left3, right3 );
//  QCOMPARE( left4, right4 );
//  QCOMPARE( left5, right5 );
*/
/*
  url.setUrl("ldap://localhost/dc=gyurco,dc=localdomain");
  url.parseQuery();
  server.setUrl( url );
  LdapConnection conn( server );
  int result = conn.connect();
  qDebug() << "connect result" << result << conn.errorString();

  LdapOperation op( conn );
  int msgid = op.search( "ou=People,dc=gyurco,dc=localdomain", LdapUrl::One, "", QStringList() );
  qDebug() << "search msgid" << msgid;
  result = op.result( msgid );
  qDebug() << "error code" << conn.ldapErrorCode() << "str:" << conn.ldapErrorString();
  while ( result == LdapOperation::RES_SEARCH_ENTRY ) {
  qDebug() << op.object().toString();
  result = op.result( msgid );
  }
  qDebug() << "error code" << conn.ldapErrorCode() << "str:" << conn.ldapErrorString();

  msgid = op.del( "ou=People,dc=gyurco,dc=localdomain" );
  qDebug() << "search msgid" << msgid;
  result = op.result( msgid );
  qDebug() << "error code" << conn.ldapErrorCode() << "str:" << conn.ldapErrorString();

  msgid = op.compare( "ou=People,dc=gyurco,dc=localdomain", "objectClass", QByteArray("top") );
  qDebug() << "search msgid" << msgid;
  result = op.result( msgid );
  qDebug() << "error code" << conn.ldapErrorCode() << "str:" << conn.ldapErrorString();

  msgid = op.compare( "ou=People,dc=gyurco,dc=localdomain", "objectClass",
                      QByteArray("inetOrgPerson") );
  qDebug() << "search msgid" << msgid;
  result = op.result( msgid );
  qDebug() << "error code" << conn.ldapErrorCode() << "str:" << conn.ldapErrorString();

  msgid = op.exop( "1.2.3.4.5.6.7.8", QByteArray("inetOrgPerson") );
  qDebug() << "search msgid" << msgid;
  result = op.result( msgid );
  qDebug() << "error code" << conn.ldapErrorCode() << "str:" << conn.ldapErrorString();
*/
/*
  }
*/
