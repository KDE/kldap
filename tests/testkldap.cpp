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
#include "testkldap.moc"

#include "ldif.h"
#include "ldapurl.h"
#include "ldapserver.h"
#include "ldapconnection.h"
#include "ldapoperation.h"

#include "kldap.h"
#include <kdebug.h>
#include <qtest_kde.h>

QTEST_KDEMAIN( KLdapTest, NoGUI )

using namespace KLDAP;

void KLdapTest::testKLdap()
{
  LdapUrl url;
  bool critical;
  
  url.setUrl("ldap://cn=manager,dc=kde,dc=org:password@localhost:3999/dc=kde,dc=org?cn,mail?sub?(objectClass=*)?x-dir=base");
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
//  url.setUrl("ldaps://cn=manager,dc=kde,dc=org:passwor@localhost:3999/dc=kde,dc=org????x-timelimt=5,x-sizelimit=6,x=pagesize=7,binddn=cn=apple,ou=berry");
  url.setUrl("ldaps://cn=manager,dc=kde,dc=org:password@localhost:3999/dc=kde,dc=org??base??x-timelimit=5");
  url.parseQuery();
  server.setUrl( url );
  QCOMPARE( url.query(), QString::fromLatin1("??base??x-timelimit=5") );
  QCOMPARE( url.url(), server.url().toString() );

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

/*  
  url.setUrl("ldap://localhost/dc=gyurco,dc=localdomain");
  url.parseQuery();
  server.setUrl( url );
  LdapConnection conn( server );
  int result = conn.connect();
  kDebug() << "connect result " << result << " " << conn.errorString() << endl;

  LdapOperation op( conn );
  int msgid = op.search( "ou=People,dc=gyurco,dc=localdomain", LdapUrl::One, "", QStringList() );
  kDebug() << "search msgid " << msgid << endl;
  result = op.result( msgid );
  kDebug() << "error code " << conn.ldapErrorCode() << " str: " << conn.ldapErrorString() << endl;
  while ( result == LdapOperation::RES_SEARCH_ENTRY ) {
    kDebug() << op.object().toString() << endl;
    result = op.result( msgid );
  }
  kDebug() << "error code " << conn.ldapErrorCode() << " str: " << conn.ldapErrorString() << endl;

  msgid = op.del( "ou=People,dc=gyurco,dc=localdomain" );
  kDebug() << "search msgid " << msgid << endl;
  result = op.result( msgid );
  kDebug() << "error code " << conn.ldapErrorCode() << " str: " << conn.ldapErrorString() << endl;

  msgid = op.compare( "ou=People,dc=gyurco,dc=localdomain", "objectClass", QByteArray("top") );
  kDebug() << "search msgid " << msgid << endl;
  result = op.result( msgid );
  kDebug() << "error code " << conn.ldapErrorCode() << " str: " << conn.ldapErrorString() << endl;

  msgid = op.compare( "ou=People,dc=gyurco,dc=localdomain", "objectClass", QByteArray("inetOrgPerson") );
  kDebug() << "search msgid " << msgid << endl;
  result = op.result( msgid );
  kDebug() << "error code " << conn.ldapErrorCode() << " str: " << conn.ldapErrorString() << endl;

  msgid = op.exop( "1.2.3.4.5.6.7.8", QByteArray("inetOrgPerson") );
  kDebug() << "search msgid " << msgid << endl;
  result = op.result( msgid );
  kDebug() << "error code " << conn.ldapErrorCode() << " str: " << conn.ldapErrorString() << endl;
*/
}
