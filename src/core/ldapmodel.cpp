/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapmodel.h"
#include "ldapserver.h"
#include <KConfig>
#include <KConfigGroup>
#include <KLDAPCore/LdapClientSearchConfig>
#include <KLDAPCore/LdapClientSearchConfigReadConfigJob>
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
        connect(job, &KLDAPCore::LdapClientSearchConfigReadConfigJob::configLoaded, this, [this](const KLDAPCore::LdapServer &server) {
            mLdapServerInfo.append({true, server});
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
        connect(job, &KLDAPCore::LdapClientSearchConfigReadConfigJob::configLoaded, this, [this](const KLDAPCore::LdapServer &server) {
            mLdapServerInfo.append({false, server});
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
    switch (static_cast<LdapRoles>(index.column())) {
    case Name:
        return serverInfo.mServer.host();
    case Enabled:
        return serverInfo.enabled;
    case Activities:
        // TODO
        return {};
    }
    return {};
}

int LdapModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    qDebug() << " mLdapServerInfo.count()" << mLdapServerInfo.count();
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
        // TODO
        case Name:
        case Enabled:
        case Activities:
            return {};
        }
    }
    return {};
}

#include "moc_ldapmodel.cpp"
