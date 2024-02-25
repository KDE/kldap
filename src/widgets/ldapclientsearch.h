/* kldapclient.h - LDAP access
 * SPDX-FileCopyrightText: 2002 Klarälvdalens Datakonsult AB
 * SPDX-FileContributor: Steffen Hansen <hansen@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldapwidgets_export.h"

#include <KLDAPCore/LdapObject>
#include <QObject>
#include <QStringList>

namespace KLDAPWidgets
{
class LdapClient;

/**
 * Describes the result returned by an LdapClientSearch query.
 *
 * @since 4.14
 */
struct LdapResultObject {
    using List = QList<LdapResultObject>;
    const LdapClient *client = nullptr;
    KLDAPCore::LdapObject object;
};

/**
 * Describes the result returned by an LdapClientSearch query.
 *
 * @since 4.5
 */
struct LdapResult {
    /**
     * A list of LdapResult objects.
     */
    using List = QList<LdapResult>;

    KLDAPCore::LdapDN dn;
    QString name; ///< The full name of the contact.
    QStringList email; ///< The list of emails of the contact.
    int clientNumber; ///< The client the contact comes from (used for sorting in a ldap-only lookup).
    int completionWeight; ///< The weight of the contact (used for sorting in a completion list).
};

/**
 * @since 4.5
 */
class KLDAPWIDGETS_EXPORT LdapClientSearch : public QObject
{
    Q_OBJECT

public:
    /**
     * Creates a new ldap client search object.
     *
     * @param parent The parent object.
     */
    explicit LdapClientSearch(QObject *parent = nullptr);

    /**
     * Creates a new ldap client search object.
     *
     * @param attr The attributes.
     * @param parent The parent object.
     */
    explicit LdapClientSearch(const QStringList &attr, QObject *parent = nullptr);

    /**
     * Destroys the ldap client search object.
     */
    ~LdapClientSearch() override;

    /**
     * Starts the LDAP search on all configured LDAP clients with the given search @p query.
     */
    void startSearch(const QString &query);

    /**
     * Cancels the currently running search query.
     */
    void cancelSearch();

    /**
     * Returns whether LDAP search is possible at all.
     *
     * @note This method can return @c false if either no LDAP is configured
     *       or the system does not support the KIO LDAP protocol.
     */
    [[nodiscard]] bool isAvailable() const;

    /**
     * Updates the completion weights for the configured LDAP clients from
     * the configuration file.
     */
    void updateCompletionWeights();

    /**
     * Returns the list of configured LDAP clients.
     */
    [[nodiscard]] QList<LdapClient *> clients() const;

    /**
     * Returns the filter for the Query
     *
     * @since 4.14
     */
    [[nodiscard]] QString filter() const;

    /**
     * Sets the filter for the Query
     *
     * @since 4.14
     */
    void setFilter(const QString &);

    /**
     * Returns the attributes, that are queried the LDAP Server.
     *
     * @since 4.14
     */
    [[nodiscard]] QStringList attributes() const;

    /**
     * Sets the attributes, that are queried the LDAP Server.
     *
     * @since 4.14
     */
    void setAttributes(const QStringList &);

    [[nodiscard]] static QStringList defaultAttributes();

Q_SIGNALS:
    /**
     * This signal is emitted whenever new contacts have been found
     * during the lookup.
     *
     * @param results The contacts in the form "Full Name <email>"
     */
    void searchData(const QStringList &results);

    /**
     * This signal is emitted whenever new contacts have been found
     * during the lookup.
     *
     * @param results The list of found contacts.
     */
    void searchData(const KLDAPWidgets::LdapResult::List &results);

    /**
     * This signal is emitted whenever new contacts have been found
     * during the lookup.
     *
     * @param results The list of found contacts.
     */
    void searchData(const KLDAPWidgets::LdapResultObject::List &results);

    /**
     * This signal is emitted whenever the lookup is complete or the
     * user has canceled the query.
     */
    void searchDone();

private:
    //@cond PRIVATE
    class LdapClientSearchPrivate;
    std::unique_ptr<LdapClientSearchPrivate> const d;
    //@endcond
};
}
Q_DECLARE_TYPEINFO(KLDAPWidgets::LdapResult, Q_RELOCATABLE_TYPE);
Q_DECLARE_TYPEINFO(KLDAPWidgets::LdapResultObject, Q_RELOCATABLE_TYPE);
