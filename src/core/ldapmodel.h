/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once
#include "kldap_core_export.h"
#include <QAbstractListModel>
namespace KLDAPCore
{
class LdapServer;
class KLDAP_CORE_EXPORT LdapModel : public QAbstractListModel
{
    Q_OBJECT
public:
    explicit LdapModel(QObject *parent = nullptr);
    ~LdapModel() override;

    enum LdapRoles {
        Name,
        Enabled,
        Activities,
        LastColumn = Activities,
    };

    [[nodiscard]] QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    [[nodiscard]] int columnCount(const QModelIndex &parent) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    KLDAP_CORE_NO_EXPORT void init();
    QList<KLDAPCore::LdapServer> mLdapServer;
};
}
