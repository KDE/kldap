/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapmodel.h"
#include "ldap_core_debug.h"
#include "ldapserver.h"
#include <KConfig>
#include <KConfigGroup>
#include <KLDAPCore/LdapClientSearchConfig>
#include <KLDAPCore/LdapClientSearchConfigReadConfigJob>
#include <KLDAPCore/LdapClientSearchConfigWriteConfigJob>
using namespace KLDAPCore;
LdapModel::LdapModel(QObject *parent)
    : QAbstractListModel{parent}
{
    init();
}

LdapModel::~LdapModel() = default;

void LdapModel::init()
{
    KConfig *config = KLDAPCore::LdapClientSearchConfig::config();
    KConfigGroup group(config, QStringLiteral("LDAP"));

    int count = group.readEntry("NumSelectedHosts", 0);
    for (int i = 0; i < count; ++i) {
        auto job = new KLDAPCore::LdapClientSearchConfigReadConfigJob(this);
        connect(job, &KLDAPCore::LdapClientSearchConfigReadConfigJob::configLoaded, this, [this, i](const KLDAPCore::LdapServer &server) {
            mLdapServerInfo.append({true, i, server});
            // TODO improve it
            beginResetModel();
            endResetModel();
        });
        job->setActive(true);
        job->setConfig(group);
        job->setServerIndex(i);
        job->start();
    }

    count = group.readEntry("NumHosts", 0);
    for (int i = 0; i < count; ++i) {
        auto job = new KLDAPCore::LdapClientSearchConfigReadConfigJob(this);
        connect(job, &KLDAPCore::LdapClientSearchConfigReadConfigJob::configLoaded, this, [this, i](const KLDAPCore::LdapServer &server) {
            mLdapServerInfo.append({false, i, server});
            // TODO improve it
            beginResetModel();
            endResetModel();
        });
        job->setActive(false);
        job->setConfig(group);
        job->setServerIndex(i);
        job->start();
    }
}

void LdapModel::save()
{
    KConfig *config = KLDAPCore::LdapClientSearchConfig::config();
    config->deleteGroup(QStringLiteral("LDAP"));

    KConfigGroup group(config, QStringLiteral("LDAP"));

    int selected = 0;
    int unselected = 0;
    for (const auto &serverInfo : std::as_const(mLdapServerInfo)) {
        if (serverInfo.enabled) {
            auto job = new KLDAPCore::LdapClientSearchConfigWriteConfigJob;
            job->setActive(true);
            job->setConfig(group);
            job->setServerIndex(selected);
            job->setServer(serverInfo.mServer);
            job->start();
            selected++;
        } else {
            auto job = new KLDAPCore::LdapClientSearchConfigWriteConfigJob;
            job->setActive(false);
            job->setConfig(group);
            job->setServerIndex(unselected);
            job->setServer(serverInfo.mServer);
            job->start();
            unselected++;
        }
    }

    group.writeEntry("NumSelectedHosts", selected);
    group.writeEntry("NumHosts", unselected);
    config->sync();
}

QList<LdapModel::ServerInfo> LdapModel::ldapServerInfo() const
{
    return mLdapServerInfo;
}

void LdapModel::setLdapServerInfo(const QList<ServerInfo> &newLdapServerInfo)
{
    mLdapServerInfo = newLdapServerInfo;
}

QVariant LdapModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return {};
    }
    const auto serverInfo = mLdapServerInfo[index.row()];
    if (role == Qt::CheckStateRole && static_cast<LdapRoles>(index.column()) == Name) {
        return serverInfo.enabled ? Qt::CheckState::Checked : Qt::CheckState::Unchecked;
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (static_cast<LdapRoles>(index.column())) {
    case Name:
        return serverInfo.mServer.host();
    case Index:
        return serverInfo.index;
    case Server:
        return QVariant::fromValue(serverInfo.mServer);
    case Activities:
        // TODO
        return {};
    }
    return {};
}

bool LdapModel::setData(const QModelIndex &modelIndex, const QVariant &value, int role)
{
    if (!modelIndex.isValid()) {
        qCWarning(LDAP_CORE_LOG) << "ERROR: invalid index";
        return false;
    }
    if (role == Qt::CheckStateRole) {
        const int idx = modelIndex.row();
        auto &serverInfo = mLdapServerInfo[idx];
        switch (static_cast<LdapRoles>(modelIndex.column())) {
        case Name: {
            const QModelIndex newIndex = index(modelIndex.row(), Name);
            Q_EMIT dataChanged(newIndex, newIndex);
            serverInfo.enabled = value.toBool();
            return true;
        }
        default:
            break;
        }
    }
    if (role != Qt::EditRole) {
        return {};
    }
    const int idx = modelIndex.row();
    auto &serverInfo = mLdapServerInfo[idx];
    switch (static_cast<LdapRoles>(modelIndex.column())) {
    case Server: {
        const QModelIndex newIndex = index(modelIndex.row(), Server);
        Q_EMIT dataChanged(newIndex, newIndex);
        serverInfo.mServer = value.value<KLDAPCore::LdapServer>();
        return true;
    }
    default:
        break;
    }
    return false;
}

int LdapModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    return mLdapServerInfo.count();
}

int LdapModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    constexpr int nbCol = static_cast<int>(LdapRoles::LastColumn) + 1;
    return nbCol;
}

QVariant LdapModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        switch (static_cast<LdapRoles>(section)) {
        case Name:
        case Index:
        case Server:
        case Activities:
            return {};
        }
    }
    return {};
}

Qt::ItemFlags LdapModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::NoItemFlags;

    if (static_cast<LdapRoles>(index.column()) == Name) {
        return Qt::ItemIsUserCheckable | QAbstractItemModel::flags(index);
    }
    return QAbstractItemModel::flags(index);
}

void LdapModel::removeServer(int index)
{
    beginRemoveRows(QModelIndex(), index, index);
    mLdapServerInfo.remove(index);
    endRemoveRows();
}

void LdapModel::insertServer(const KLDAPCore::LdapServer &server)
{
    beginInsertRows(QModelIndex(), 0, mLdapServerInfo.count() - 1);
    // TODO verify it
    mLdapServerInfo.append({true, 0, server});
    endInsertRows();
}

#include "moc_ldapmodel.cpp"
