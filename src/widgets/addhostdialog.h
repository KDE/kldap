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
 * \class KLDAPWidgets::AddHostDialog
 * \ inmodule LdapWidgets
 * \inheaderfile KLDAPWidgets/AddHostDialog
 *
 * \brief The AddHostDialog class
 * \author Laurent Montel <montel@kde.org>
 */
class KLDAPWIDGETS_EXPORT AddHostDialog : public QDialog
{
    Q_OBJECT

public:
    /*!
     * Constructs an AddHostDialog with the given LDAP server configuration.
     * \param server the LDAP server configuration to edit
     * \param parent the parent widget
     */
    explicit AddHostDialog(KLDAPCore::LdapServer *server, QWidget *parent = nullptr);

    /*!
     * Destroys the AddHostDialog.
     */
    ~AddHostDialog() override;

Q_SIGNALS:
    /*!
     * Emitted when the dialog content has changed.
     * \param changed true if the content has been modified
     */
    void changed(bool);

private:
    KLDAPWIDGETS_NO_EXPORT void slotHostEditChanged(const QString &);
    KLDAPWIDGETS_NO_EXPORT void slotOk();
    KLDAPWIDGETS_NO_EXPORT void readConfig();
    KLDAPWIDGETS_NO_EXPORT void writeConfig();
    std::unique_ptr<AddHostDialogPrivate> const d;
};
}
