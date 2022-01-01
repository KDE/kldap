/*
 * SPDX-FileCopyrightText: 2020-2022 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearchconfigreadconfigjobtest.h"
#include "widgets/ldapclientsearchconfigreadconfigjob.h"
#include <QTest>
QTEST_MAIN(LdapClientSearchConfigReadConfigJobTest)
LdapClientSearchConfigReadConfigJobTest::LdapClientSearchConfigReadConfigJobTest(QObject *parent)
    : QObject(parent)
{
}

void LdapClientSearchConfigReadConfigJobTest::shouldHaveDefaultValues()
{
    KLDAP::LdapClientSearchConfigReadConfigJob job;
    QVERIFY(!job.active());
    QCOMPARE(job.serverIndex(), -1);
    QVERIFY(!job.canStart());
}
