/*
 * SPDX-FileCopyrightText: 2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LDAPCLIENTSEARCHCONFIGREADCONFIGJOB_H
#define LDAPCLIENTSEARCHCONFIGREADCONFIGJOB_H
#include <QObject>
namespace KLDAP {
class LdapClientSearchConfigReadConfigJob : public QObject
{
    Q_OBJECT
public:
    explicit LdapClientSearchConfigReadConfigJob(QObject *parent = nullptr);
    ~LdapClientSearchConfigReadConfigJob() override;

    void start();
};

}
#endif // LDAPCLIENTSEARCHCONFIGREADCONFIGJOB_H
