/*
 * SPDX-FileCopyrightText: 2020-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <QObject>

class LdapClientSearchConfigReadConfigJobTest : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfigReadConfigJobTest(QObject *parent = nullptr);
    ~LdapClientSearchConfigReadConfigJobTest() override = default;
private Q_SLOTS:
    void shouldHaveDefaultValues();
};
