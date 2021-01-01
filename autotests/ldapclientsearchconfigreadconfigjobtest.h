/*
 * SPDX-FileCopyrightText: 2020-2021 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPCLIENTSEARCHCONFIGREADCONFIGJOBTEST_H
#define LDAPCLIENTSEARCHCONFIGREADCONFIGJOBTEST_H

#include <QObject>

class LdapClientSearchConfigReadConfigJobTest : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfigReadConfigJobTest(QObject *parent = nullptr);
    ~LdapClientSearchConfigReadConfigJobTest() = default;
private Q_SLOTS:
    void shouldHaveDefaultValues();
};

#endif // LDAPCLIENTSEARCHCONFIGREADCONFIGJOBTEST_H
