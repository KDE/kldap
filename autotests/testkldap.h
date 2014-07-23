/*
  Copyright (c) 2006 Volker Krause <vkrause@kde.org>

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

#ifndef TESTKLDAP_H
#define TESTKLDAP_H

#include <QtCore/QObject>
#include <ldapmodel.h>
#include <ldapobject.h>
#include <ldapsearch.h>

using namespace KLDAP;

class KLdapTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    //void testKLdap();

    void initTestCase();
    void cleanupTestCase();

    void testLdapUrl();
    void testBer();
    void testLdapConnection();
    void testLdapSearch();
    void testLdapDN();
    void testLdapModel();

public Q_SLOTS:
    void searchResult(KLDAP::LdapSearch *search);
    void searchData(KLDAP::LdapSearch *search, const KLDAP::LdapObject &obj);

private:
    QString m_url;
    LdapSearch *m_search;
    LdapObjects m_objects;
    LdapModel *m_model;
};

#endif
