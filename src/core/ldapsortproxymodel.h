// SPDX-FileCopyrightText: 2024-2026 Laurent Montel <montel@kde.org>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once
#include "kldap_core_export.h"

#include <QSortFilterProxyModel>

namespace KLDAPCore
{
class LdapActivitiesAbstract;
/*!
 * \class KLDAPCore::LdapSortProxyModel
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapSortProxyModel
 *
 * \brief The LdapSortProxyModel class
 */
class KLDAP_CORE_EXPORT LdapSortProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    /*!
     * Constructs a LdapSortProxyModel with the given parent object.
     * \param parent the parent QObject
     */
    explicit LdapSortProxyModel(QObject *parent);

    /*!
     * Destroys the LdapSortProxyModel.
     */
    ~LdapSortProxyModel() override;

    /*!
     * Returns the LDAP Activities Abstract instance used for filtering.
     * \return the LDAP Activities Abstract instance, or nullptr if not set
     */
    [[nodiscard]] LdapActivitiesAbstract *ldapActivitiesAbstract() const;

    /*!
     * Sets the LDAP Activities Abstract instance for filtering.
     * \param newldapActivitiesAbstract the LDAP Activities Abstract instance
     */
    void setLdapActivitiesAbstract(LdapActivitiesAbstract *newldapActivitiesAbstract);

    /*!
     * Returns whether Plasma Activities support is enabled.
     * \return true if Plasma Activities are enabled, false otherwise
     */
    [[nodiscard]] bool enablePlasmaActivities() const;

    /*!
     * Sets whether Plasma Activities support is enabled.
     * \param newEnablePlasmaActivities true to enable Plasma Activities
     */
    void setEnablePlasmaActivities(bool newEnablePlasmaActivities);

protected:
    /*!
     * Filters rows based on the current activity settings.
     * \param source_row the row in the source model
     * \param source_parent the parent index in the source model
     * \return true if the row should be accepted by the filter
     */
    [[nodiscard]] bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;

    /*!
     * Compares two items for sorting purposes.
     * \param source_left the left index to compare
     * \param source_right the right index to compare
     * \return true if the left item should be sorted before the right item
     */
    [[nodiscard]] bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;

private:
    KLDAP_CORE_NO_EXPORT void slotInvalidateFilter();
    LdapActivitiesAbstract *mLdapActivitiesAbstract = nullptr;
    bool mEnablePlasmaActivities = false;
};
}
