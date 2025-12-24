/*
  This file is part of libkldap.

  SPDX-FileCopyrightText: 2002-2010 Tobias Koenig <tokoe@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kldapwidgets_export.h"
#include <QDialog>

namespace KLDAPCore
{
class LdapServer;
}
namespace KLDAPWidgets
{
class AddHostDialogPrivate;
/*!
 * \brief The AddHostDialog class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAPWIDGETS_EXPORT AddHostDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AddHostDialog(KLDAPCore::LdapServer *server, QWidget *parent = nullptr);
    ~AddHostDialog() override;

Q_SIGNALS:
    void changed(bool);

private:
    KLDAPWIDGETS_NO_EXPORT void slotHostEditChanged(const QString &);
    KLDAPWIDGETS_NO_EXPORT void slotOk();
    KLDAPWIDGETS_NO_EXPORT void readConfig();
    KLDAPWIDGETS_NO_EXPORT void writeConfig();
    std::unique_ptr<AddHostDialogPrivate> const d;
};
}
