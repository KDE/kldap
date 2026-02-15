/*
 * SPDX-FileCopyrightText: 2024-2026 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldapwidgets_export.h"

#include <QWidget>

class QTreeView;
class QPushButton;
class QToolButton;
class QCheckBox;

namespace KLDAPCore
{
class LdapClientSearchConfig;
class LdapModel;
class LdapSortProxyModel;
class LdapActivitiesAbstract;
}

namespace KLDAPWidgets
{
/*!
 * \class KLDAPWidgets::LdapConfigureWidgetNg
 * \ inmodule LdapWidgets
 * \inheaderfile KLDAPWidgets/LdapConfigureWidgetNg
 *
 * \brief The LdapConfigureWidgetNg class
 * \author Laurent Montel <montel@kde.org>
 */
class KLDAPWIDGETS_EXPORT LdapConfigureWidgetNg : public QWidget
{
    Q_OBJECT
public:
    /*!
     * Constructs a LdapConfigureWidgetNg with the given parent widget.
     * \param parent the parent widget
     */
    explicit LdapConfigureWidgetNg(QWidget *parent = nullptr);

    /*!
     * Destroys the LdapConfigureWidgetNg.
     */
    ~LdapConfigureWidgetNg() override;

    /*!
     * Saves the current configuration.
     */
    void save();

    /*!
     * Loads the configuration.
     */
    void load();

    /*!
     * Returns whether Plasma Activities support is enabled.
     * \return true if Plasma Activities is enabled, false otherwise
     */
    [[nodiscard]] bool enablePlasmaActivities() const;

    /*!
     * Sets whether Plasma Activities support is enabled.
     * \param newEnablePlasmaActivities true to enable Plasma Activities, false to disable
     */
    void setEnablePlasmaActivities(bool newEnablePlasmaActivities);

    /*!
     * Returns the LDAP Activities Abstract instance.
     * \return the LDAP Activities Abstract instance, or nullptr if not set
     */
    [[nodiscard]] KLDAPCore::LdapActivitiesAbstract *ldapActivitiesAbstract() const;

    /*!
     * Sets the LDAP Activities Abstract instance.
     * \param newldapActivitiesAbstract the LDAP Activities Abstract instance to set
     */
    void setLdapActivitiesAbstract(KLDAPCore::LdapActivitiesAbstract *newldapActivitiesAbstract);

Q_SIGNALS:
    /*!
     * Emitted when the configuration has changed.
     * \param changed true if the configuration has been modified
     */
    void changed(bool);

private:
    KLDAPWIDGETS_NO_EXPORT void slotAddHost();
    KLDAPWIDGETS_NO_EXPORT void slotEditHost();
    KLDAPWIDGETS_NO_EXPORT void slotRemoveHost();
    KLDAPWIDGETS_NO_EXPORT void updateButtons();
    KLDAPWIDGETS_NO_EXPORT void slotMoveUp();
    KLDAPWIDGETS_NO_EXPORT void slotMoveDown();
    KLDAPWIDGETS_NO_EXPORT void initGUI();
    QTreeView *mHostListView = nullptr;

    QPushButton *mAddButton = nullptr;
    QPushButton *mEditButton = nullptr;
    QPushButton *mRemoveButton = nullptr;

    QToolButton *mUpButton = nullptr;
    QToolButton *mDownButton = nullptr;
    KLDAPCore::LdapClientSearchConfig *const mClientSearchConfig;
    KLDAPCore::LdapModel *const mLdapModel;
    KLDAPCore::LdapSortProxyModel *const mLdapSortProxyModel;
    QCheckBox *const mLdapOnCurrentActivity;
};
}
