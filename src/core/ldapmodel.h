/*
 * SPDX-FileCopyrightText: 2024-2025 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once
#include "kldap_core_export.h"
#include <KLDAPCore/LdapServer>
#include <QAbstractListModel>
namespace KLDAPCore
{
/*!
 * \class KLDAPCore::LdapModel
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapModel
 *
 * \brief The LdapModel class
 */
class KLDAP_CORE_EXPORT LdapModel : public QAbstractListModel
{
    Q_OBJECT
public:
    /*!
     */
    explicit LdapModel(QObject *parent = nullptr);
    /*!
     */
    ~LdapModel() override;

    enum LdapRoles {
        Name,
        Index,
        Activities,
        EnabledActivitiesRole,
        Server,
        LastColumn = Server,
    };

    struct ServerInfo {
        bool enabled = false;
        int index = 0;
        KLDAPCore::LdapServer server;
    };

    /*!
     */
    [[nodiscard]] QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    /*!
     */
    [[nodiscard]] int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    /*!
     */
    [[nodiscard]] int columnCount(const QModelIndex &parent) const override;
    /*!
     */
    bool setData(const QModelIndex &modelIndex, const QVariant &value, int role) override;

    /*!
     */
    [[nodiscard]] QList<ServerInfo> ldapServerInfo() const;
    /*!
     */
    void setLdapServerInfo(const QList<ServerInfo> &newLdapServerInfo);

    /*!
     */
    [[nodiscard]] Qt::ItemFlags flags(const QModelIndex &index) const override;

    /*!
     */
    void save();
    /*!
     */
    void load();

    /*!
     */
    void insertServer(const KLDAPCore::LdapServer &server);

    /*!
     */
    void removeServer(int index);

private:
    KLDAP_CORE_NO_EXPORT void init();
    QList<ServerInfo> mLdapServerInfo;
};
}
Q_DECLARE_METATYPE(KLDAPCore::LdapModel::ServerInfo)
Q_DECLARE_TYPEINFO(KLDAPCore::LdapModel::ServerInfo, Q_RELOCATABLE_TYPE);
