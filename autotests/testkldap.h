/*
  SPDX-FileCopyrightText: 2006 Volker Krause <vkrause@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QObject>
#include <ldapobject.h>
#include <ldapsearch.h>

using namespace KLDAP;

class KLdapTest : public QObject
{
    Q_OBJECT
public:
    explicit KLdapTest(QObject *parent = nullptr);
    ~KLdapTest() override = default;

private Q_SLOTS:
    // void testKLdap();

    void initTestCase();
    void cleanupTestCase();

    void testLdapUrl();
    void testBer();
    void testLdapConnection();
    void testLdapSearch();
    void testLdapDN();
    void testLdapModel();

private:
    void searchResult(KLDAP::LdapSearch *search);
    void searchData(KLDAP::LdapSearch *search, const KLDAP::LdapObject &obj);
    QString m_url;
    LdapSearch *m_search = nullptr;
    LdapObjects m_objects;
};
