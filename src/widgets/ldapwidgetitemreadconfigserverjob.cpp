/*
 * SPDX-FileCopyrightText: 2020-2023 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapwidgetitemreadconfigserverjob.h"
#include "ldapclientsearchconfigreadconfigjob.h"
#include "ldapwidgetitem_p.h"
using namespace KLDAPWidgets;
LdapWidgetItemReadConfigServerJob::LdapWidgetItemReadConfigServerJob(QObject *parent)
    : QObject(parent)
{
}

LdapWidgetItemReadConfigServerJob::~LdapWidgetItemReadConfigServerJob() = default;

void LdapWidgetItemReadConfigServerJob::start()
{
    auto job = new LdapClientSearchConfigReadConfigJob(this);
    connect(job, &LdapClientSearchConfigReadConfigJob::configLoaded, this, &LdapWidgetItemReadConfigServerJob::slotConfigLoaded);
    job->setActive(mActive);
    job->setConfig(mConfig);
    job->setServerIndex(mCurrentIndex);
    job->start();
}

void LdapWidgetItemReadConfigServerJob::slotConfigLoaded(const KLDAPCore::LdapServer &server)
{
    mLdapWidgetItem->setServer(server);
    deleteLater();
}

LdapWidgetItem *LdapWidgetItemReadConfigServerJob::ldapWidgetItem() const
{
    return mLdapWidgetItem;
}

void LdapWidgetItemReadConfigServerJob::setLdapWidgetItem(LdapWidgetItem *ldapWidgetItem)
{
    mLdapWidgetItem = ldapWidgetItem;
}

int LdapWidgetItemReadConfigServerJob::currentIndex() const
{
    return mCurrentIndex;
}

void LdapWidgetItemReadConfigServerJob::setCurrentIndex(int currentIndex)
{
    mCurrentIndex = currentIndex;
}

bool LdapWidgetItemReadConfigServerJob::active() const
{
    return mActive;
}

void LdapWidgetItemReadConfigServerJob::setActive(bool active)
{
    mActive = active;
}

KConfigGroup LdapWidgetItemReadConfigServerJob::config() const
{
    return mConfig;
}

void LdapWidgetItemReadConfigServerJob::setConfig(const KConfigGroup &config)
{
    mConfig = config;
}
