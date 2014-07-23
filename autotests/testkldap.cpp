/*
  This file is part of libkdepim.

  Copyright (c) 2004 Tobias Koenig <tokoe@kde.org>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; see the file COPYING.LIB.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#include "testkldap.h"

#include "ldif.h"
#include "ldapdn.h"
#include "ldapurl.h"
#include "ldapserver.h"
#include "ldapconnection.h"
#include "ldapmodel.h"
#include "ldapoperation.h"
#include "ldapsearch.h"
#include "ber.h"

#include <qdebug.h>
#include <qtest.h>
#include <QFile>
QTEST_MAIN(KLdapTest)

void KLdapTest::initTestCase()
{
    /*
      Read in the connection details of an LDAP server to use for testing.
      You should copy the file testurl.txt.tmpl to testurl.txt and specify a url in this file.
      The specified server should not be a production server in case we break anything here.
      You have been warned!
    */
    m_search = 0;
    m_model = 0;

    QString filename(QLatin1String("testurl.txt"));
    QFile file(filename);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        stream >> m_url;
        file.close();
    }
//    else
//        QCOMPARE( 0, 1 );

    m_search = new LdapSearch;

    /* Let's also create an LdapModel object */
    m_model = new LdapModel(this);
}

void KLdapTest::testBer()
{
    Ber ber1, ber2, ber3, ber4, ber5, ber6, ber7;
    Ber bber;
    QByteArray flat;

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

    ber1.printf(QLatin1String("i"), ainteger);
    ber2.printf(QLatin1String("o"), &aoctetString1);
    ber3.printf(QLatin1String("O"), &aoctetString2);
    ber4.printf(QLatin1String("s"), &aoctetString3);
    ber5.printf(QLatin1String("{v}"), &alist1);
    ber6.printf(QLatin1String("{V}"), &alist2);
    ber7.printf(QLatin1String("oi{v}O"), &aoctetString1, ainteger, &alist2, &aoctetString2);

    //test integer:
    bber = ber1;
    bber.scanf(QLatin1String("i"), &binteger);
    QCOMPARE(ainteger, binteger);

    //test octet strings:
    bber = ber2;
    bber.scanf(QLatin1String("o"), &boctetString1);
    QCOMPARE(aoctetString1, boctetString1);
    bber = ber3;
    bber.scanf(QLatin1String("o"), &boctetString2);
    QCOMPARE(aoctetString2, boctetString2);
    bber = ber4;
    bber.scanf(QLatin1String("o"), &boctetString3);
    QCOMPARE(aoctetString3, boctetString3);

    //test sequence of octet strings:
    bber = ber5;
    bber.scanf(QLatin1String("v"), &blist1);
    QCOMPARE(alist1, blist1);

    bber = ber6;
    bber.scanf(QLatin1String("v"), &blist2);
    QCOMPARE(alist2, blist2);

    //complex tests
    boctetString1 = boctetString2 = boctetString3 = QByteArray();
    binteger = 0;
    blist1.clear();
    blist2.clear();

    bber = ber7;
    bber.scanf(QLatin1String("oivO"), &boctetString1, &binteger, &blist2, &boctetString2);
    QCOMPARE(aoctetString1, boctetString1);
    QCOMPARE(aoctetString2, boctetString2);
    QCOMPARE(alist2, blist2);
    QCOMPARE(ainteger, binteger);
}

void KLdapTest::cleanupTestCase()
{
    delete m_search;
    delete m_model;
}

void KLdapTest::testLdapUrl()
{
    // Test LdapUrl using some hardwired values so that we know what to compare to
    LdapUrl url;
    bool critical;

    url.setUrl(QLatin1String("ldap://cn=manager,dc=kde,dc=org:password@localhost:3999/"
                             "dc=kde,dc=org?cn,mail?sub?(objectClass=*)?x-dir=base"));
    url.parseQuery();

    QCOMPARE(url.userName(), QString::fromLatin1("cn=manager,dc=kde,dc=org"));
    QCOMPARE(url.password(), QString::fromLatin1("password"));
    QCOMPARE(url.dn(), LdapDN(QLatin1String("dc=kde,dc=org")));
    QCOMPARE(url.scope(), LdapUrl::Sub);
    QCOMPARE(url.attributes().at(0), QString::fromLatin1("cn"));
    QCOMPARE(url.attributes().at(1), QString::fromLatin1("mail"));
    QCOMPARE(url.filter(), QString::fromLatin1("(objectClass=*)"));
    QCOMPARE(url.extension(QString::fromLatin1("x-dir"), critical),
             QString::fromLatin1("base"));
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
    connect(m_search, SIGNAL(result(KLDAP::LdapSearch *)),
            this, SLOT(searchResult(KLDAP::LdapSearch *)));
    connect(m_search, SIGNAL(data(KLDAP::LdapSearch *, KLDAP::LdapObject)),
            this, SLOT(searchData(KLDAP::LdapSearch *, KLDAP::LdapObject)));
    bool success = m_search->search(url);
    while (QCoreApplication::hasPendingEvents()) {
        qApp->processEvents();
    }

    QEXPECT_FAIL("", "Will fail since no server is available for testing", Abort);
    QCOMPARE(success, true);

    qDebug() << "Search found" << m_objects.size() << "matching entries";
}

void KLdapTest::searchResult(KLDAP::LdapSearch *search)
{
    qDebug();
    int err = search->error();
    if (err) {
        qDebug() << "Search returned the following error:" << search->errorString();
    }
    QCOMPARE(err, 0);
}

void KLdapTest::searchData(KLDAP::LdapSearch *search, const KLDAP::LdapObject &obj)
{
    Q_UNUSED(search);
    //qDebug();
    //qDebug() << "Object:";
    //qDebug() << obj.toString();
    m_objects.append(obj);
}

void KLdapTest::testLdapDN()
{
    QString strDN(QLatin1String("uid=Test\\+Person+ou=accounts\\,outgoing,dc=kde,dc=org"));
    LdapDN dn(strDN);
    QCOMPARE(dn.isValid(), true);
    QCOMPARE(dn.rdnString(), QLatin1String("uid=Test\\+Person+ou=accounts\\,outgoing"));
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

    // Let's use this connection with the model
    m_model->setConnection(conn);

    while (QCoreApplication::hasPendingEvents()) {
        qApp->processEvents();
    }

    QModelIndex rootIndex = QModelIndex();
    QVariant data = m_model->data(rootIndex, Qt::DisplayRole);
    qDebug() << "Root Item Distinguished Name =" << data.toString();

    QVERIFY(m_model->hasChildren(rootIndex) == true);
    QVERIFY(m_model->canFetchMore(rootIndex) == false);
}

/*
  void KLdapTest::testKLdap()
  {
  LdapUrl url;
  bool critical;

  url.setUrl("ldap://cn=manager,dc=kde,dc=org:password@localhost:3999"
             "/dc=kde,dc=org?cn,mail?sub?(objectClass=*)?x-dir=base");
  url.parseQuery();

  QCOMPARE( url.user(), QString::fromLatin1("cn=manager,dc=kde,dc=org") );
  QCOMPARE( url.password(), QString::fromLatin1("password") );
  QCOMPARE( url.dn(), QString::fromLatin1("dc=kde,dc=org") );
  QCOMPARE( url.scope(), LdapUrl::Sub );
  QCOMPARE( url.attributes().at(0), QString::fromLatin1("cn") );
  QCOMPARE( url.attributes().at(1), QString::fromLatin1("mail") );
  QCOMPARE( url.filter(), QString::fromLatin1("(objectClass=*)") );
  QCOMPARE( url.extension(QString::fromLatin1("x-dir"), critical), QString::fromLatin1("base") );

  url.setDn("ou=People,dc=kde,dc=org");
  QCOMPARE( url.dn(), QString::fromLatin1("ou=People,dc=kde,dc=org") );
  url.setDn("/ou=People,dc=kde,dc=org");
  QCOMPARE( url.dn(), QString::fromLatin1("ou=People,dc=kde,dc=org") );

  LdapServer server;
//  url.setUrl("ldaps://cn=manager,dc=kde,dc=org:passwor@localhost:3999/"
               "dc=kde,dc=org????x-timelimt=5,x-sizelimit=6,x=pagesize=7,binddn=cn=apple,ou=berry");
url.setUrl("ldaps://cn=manager,dc=kde,dc=org:password@localhost:3999/"
           "dc=kde,dc=org??base??x-timelimit=5");
url.parseQuery();
server.setUrl( url );
QCOMPARE( url.query(), QString::fromLatin1("??base??x-timelimit=5") );
QCOMPARE( url.url(), server.url().url() );

LdapControl c1;
c1.setControl( QString::fromLatin1("1.2.3.4.5.6"), QByteArray("abcdefg"), true );
//test copy constructor
LdapControl c2(c1);
QCOMPARE( c2.oid(), QString::fromLatin1("1.2.3.4.5.6") );
QCOMPARE( c2.value(), QByteArray("abcdefg") );
QCOMPARE( c2.critical(), true );
//test assignment operator
LdapControl c3;
c3 = c1;
QCOMPARE( c3.oid(), QString::fromLatin1("1.2.3.4.5.6") );
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
