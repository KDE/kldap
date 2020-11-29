/*
 * SPDX-FileCopyrightText: 2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapwidgetitemreadconfigserverjob.h"
#include "ldapwidgetitem_p.h"
#include "ldapclientsearchconfigreadconfigjob.h"
using namespace KLDAP;
LdapWidgetItemReadConfigServerJob::LdapWidgetItemReadConfigServerJob(QObject *parent)
    : QObject(parent)
{

}

LdapWidgetItemReadConfigServerJob::~LdapWidgetItemReadConfigServerJob()
{

}

void LdapWidgetItemReadConfigServerJob::start()
{
    auto job = new LdapClientSearchConfigReadConfigJob(this);
    connect(job, &LdapClientSearchConfigReadConfigJob::configLoaded, this, &LdapWidgetItemReadConfigServerJob::slotConfigLoaded);
    job->setActive(mActive);
    job->setConfig(mConfig);
    job->setServerIndex(mCurrentIndex);
    job->start();
}

void LdapWidgetItemReadConfigServerJob::slotConfigLoaded(const KLDAP::LdapServer &server)
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
