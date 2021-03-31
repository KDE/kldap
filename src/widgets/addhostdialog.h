/*
  This file is part of libkldap.

  SPDX-FileCopyrightText: 2002-2010 Tobias Koenig <tokoe@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kldap_export.h"
#include <QDialog>

namespace KLDAP
{
class LdapServer;
class AddHostDialogPrivate;
/**
 * @brief The AddHostDialog class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAP_EXPORT AddHostDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AddHostDialog(KLDAP::LdapServer *server, QWidget *parent = nullptr);
    ~AddHostDialog();

Q_SIGNALS:
    void changed(bool);

private Q_SLOTS:
    void slotHostEditChanged(const QString &);
    void slotOk();

private:
    AddHostDialogPrivate *const d;
};
}

