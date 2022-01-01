/*
 * SPDX-FileCopyrightText: 2020-2022 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapsearchclientreadconfigserverjob.h"
#include "ldapclient.h"
#include "ldapclient_debug.h"
#include "ldapclientsearchconfigreadconfigjob.h"
using namespace KLDAP;
LdapSearchClientReadConfigServerJob::LdapSearchClientReadConfigServerJob(QObject *parent)
    : QObject(parent)
{
}

LdapSearchClientReadConfigServerJob::~LdapSearchClientReadConfigServerJob() = default;

void LdapSearchClientReadConfigServerJob::start()
{
    if (!canStart()) {
        qCWarning(LDAPCLIENT_LOG) << " Impossible to start LdapSearchClientReadConfigServerJob";
        deleteLater();
        return;
    }
    auto job = new LdapClientSearchConfigReadConfigJob(this);
    connect(job, &LdapClientSearchConfigReadConfigJob::configLoaded, this, &LdapSearchClientReadConfigServerJob::slotConfigLoaded);
    job->setActive(mActive);
    job->setConfig(mConfig);
    job->setServerIndex(mCurrentIndex);
    job->start();
}

bool LdapSearchClientReadConfigServerJob::canStart() const
{
    return mCurrentIndex != -1 && mConfig.isValid();
}

void LdapSearchClientReadConfigServerJob::slotConfigLoaded(const KLDAP::LdapServer &server)
{
    mLdapClient->setServer(server);
    deleteLater();
}

LdapClient *LdapSearchClientReadConfigServerJob::ldapClient() const
{
    return mLdapClient;
}

void LdapSearchClientReadConfigServerJob::setLdapClient(LdapClient *ldapClient)
{
    mLdapClient = ldapClient;
}

int LdapSearchClientReadConfigServerJob::currentIndex() const
{
    return mCurrentIndex;
}

void LdapSearchClientReadConfigServerJob::setCurrentIndex(int currentIndex)
{
    mCurrentIndex = currentIndex;
}

bool LdapSearchClientReadConfigServerJob::active() const
{
    return mActive;
}

void LdapSearchClientReadConfigServerJob::setActive(bool active)
{
    mActive = active;
}

KConfigGroup LdapSearchClientReadConfigServerJob::config() const
{
    return mConfig;
}

void LdapSearchClientReadConfigServerJob::setConfig(const KConfigGroup &config)
{
    mConfig = config;
}
