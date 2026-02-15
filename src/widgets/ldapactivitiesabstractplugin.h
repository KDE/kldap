/*
  SPDX-FileCopyrightText: 2024-2026 Laurent Montel <montel@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once
#include "kldapwidgets_export.h"
#include <QWidget>
namespace KLDAPWidgets
{
/*!
 * \class KLDAPWidgets::LdapActivitiesAbstractPlugin
 * \ inmodule LdapWidgets
 * \inheaderfile KLDAPWidgets/LdapActivitiesAbstractPlugin
 *
 * \brief The LdapActivitiesAbstractPlugin class
 */
class KLDAPWIDGETS_EXPORT LdapActivitiesAbstractPlugin : public QWidget
{
    Q_OBJECT
public:
    struct ActivitySettings {
        QStringList activities;
        bool enabled = false;
    };

    /*!
     * Constructs a LdapActivitiesAbstractPlugin with the given parent widget.
     * \param parent the parent widget
     */
    explicit LdapActivitiesAbstractPlugin(QWidget *parent = nullptr);

    /*!
     * Destroys the LdapActivitiesAbstractPlugin.
     */
    ~LdapActivitiesAbstractPlugin() override;

    /*!
     * Returns the activities settings for this plugin.
     * \return the activities settings
     */
    [[nodiscard]] virtual LdapActivitiesAbstractPlugin::ActivitySettings activitiesSettings() const = 0;

    /*!
     * Sets the activities settings for this plugin.
     * \param activitySettings the activities settings to set
     */
    virtual void setActivitiesSettings(const LdapActivitiesAbstractPlugin::ActivitySettings &activitySettings) = 0;
};
}
