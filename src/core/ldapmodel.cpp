/*
 * SPDX-FileCopyrightText: 2024-2025 Laurent Montel <montel@kde.org>
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
using namespace Qt::Literals::StringLiterals;
LdapModel::LdapModel(QObject *parent)
    : QAbstractListModel{parent}
{
}

LdapModel::~LdapModel() = default;

void LdapModel::init()
{
    KConfig *config = KLDAPCore::LdapClientSearchConfig::config();
    KConfigGroup group(config, u"LDAP"_s);

    const int countSelectedHost = group.readEntry("NumSelectedHosts", 0);
    for (int i = 0; i < countSelectedHost; ++i) {
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

    const int countUnselectedHost = group.readEntry("NumHosts", 0);
    for (int i = 0; i < countUnselectedHost; ++i) {
        auto job = new KLDAPCore::LdapClientSearchConfigReadConfigJob(this);
        connect(job, &KLDAPCore::LdapClientSearchConfigReadConfigJob::configLoaded, this, [this, i, countSelectedHost](const KLDAPCore::LdapServer &server) {
            mLdapServerInfo.append({false, i + countSelectedHost, server});
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

void LdapModel::load()
{
    mLdapServerInfo.clear();
    init();
}

void LdapModel::save()
{
    KConfig *config = KLDAPCore::LdapClientSearchConfig::config();
    config->deleteGroup(u"LDAP"_s);

    KConfigGroup group(config, u"LDAP"_s);

    int selected = 0;
    int unselected = 0;
    for (const auto &serverInfo : std::as_const(mLdapServerInfo)) {
        if (serverInfo.enabled) {
            auto job = new KLDAPCore::LdapClientSearchConfigWriteConfigJob;
            job->setActive(true);
            job->setConfig(group);
            job->setServerIndex(selected);
            job->setServer(serverInfo.server);
            job->start();
            selected++;
        } else {
            auto job = new KLDAPCore::LdapClientSearchConfigWriteConfigJob;
            job->setActive(false);
            job->setConfig(group);
            job->setServerIndex(unselected);
            job->setServer(serverInfo.server);
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
    if (role == Qt::DisplayRole) {
        switch (static_cast<LdapRoles>(index.column())) {
        case Name:
            return serverInfo.server.host();
        case Index:
            return serverInfo.index;
        case Server:
            return QVariant::fromValue(serverInfo.server);
        case Activities:
            qDebug() << " serverInfo.server.activities()" << serverInfo.server.activities();
            return serverInfo.server.activities();
        case EnabledActivitiesRole:
            return serverInfo.server.enablePlasmaActivities();
        }
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
        switch (static_cast<LdapRoles>(modelIndex.column())) {
        case Name: {
            const QModelIndex newIndex = index(modelIndex.row(), Name);
            auto &serverInfo = mLdapServerInfo[idx];
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
        serverInfo.server = value.value<KLDAPCore::LdapServer>();
        return true;
    }
    case Index: {
        const QModelIndex newIndex = index(modelIndex.row(), Index);
        // qDebug() << " serverInfo.server" << serverInfo.server << " value.toInt()" << value.toInt();
        serverInfo.index = value.toInt();
        Q_EMIT dataChanged(newIndex, newIndex);
        return true;
    }
    default:
        break;
    }
    return false;
}

int LdapModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) // flat model
        return 0;
    return mLdapServerInfo.count();
}

int LdapModel::columnCount([[maybe_unused]] const QModelIndex &parent) const
{
    constexpr int nbCol = static_cast<int>(LdapRoles::LastColumn) + 1;
    return nbCol;
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
    beginInsertRows(QModelIndex(), mLdapServerInfo.count() - 1, mLdapServerInfo.count() - 1);
    mLdapServerInfo.append({true, 0, server});
    endInsertRows();
}

#include "moc_ldapmodel.cpp"
