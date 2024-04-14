/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <QAbstractListModel>
namespace KLDAPCore
{
class LdapModel : public QAbstractListModel
{
public:
    explicit LdapModel(QObject *parent = nullptr);
    ~LdapModel() override;
};
}
