/*
 * SPDX-FileCopyrightText: 2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapwidgetitemreadconfigserverjob.h"
#include "ldapwidgetitem_p.h"
using namespace KLDAP;
LdapWidgetItemReadConfigServerJob::LdapWidgetItemReadConfigServerJob(QObject *parent)
    : QObject(parent)
{

}

LdapWidgetItemReadConfigServerJob::~LdapWidgetItemReadConfigServerJob()
{

}

LdapWidgetItem *LdapWidgetItemReadConfigServerJob::ldapWidgetItem() const
{
    return mLdapWidgetItem;
}

void LdapWidgetItemReadConfigServerJob::setLdapWidgetItem(LdapWidgetItem *ldapWidgetItem)
{
    mLdapWidgetItem = ldapWidgetItem;
}
