/* kldapclient.h - LDAP access
 * SPDX-FileCopyrightText: 2002 Klarälvdalens Datakonsult AB
 * SPDX-FileContributor: Steffen Hansen <hansen@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldap_core_export.h"
#include <QObject>
#include <QStringList>
#include <memory>

namespace KLDAPCore
{
class LdapObject;
class LdapServer;
/*!
 * \class KLDAPCore::LdapClient
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapClient
 *
 * \brief An object that represents a configured LDAP server.
 *
 * This class represents a client that to an LDAP server that
 * can be used for LDAP lookups. Every client is identified by
 * a unique numeric id.
 *
 * \since 4.5
 */
class KLDAP_CORE_EXPORT LdapClient : public QObject
{
    Q_OBJECT

public:
    /*!
     * Creates a new ldap client.
     *
     * \a clientNumber The unique number of this client.
     * \a parent The parent object.
     */
    explicit LdapClient(int clientNumber, QObject *parent = nullptr);

    /*!
     * Destroys the ldap client.
     */
    ~LdapClient() override;

    /*!
     * Returns the number of this client.
     */
    [[nodiscard]] int clientNumber() const;

    /*!
     * Returns whether this client is currently running
     * a search query.
     */
    [[nodiscard]] bool isActive() const;

    /*!
     * Sets the completion \a weight of this client.
     *
     * This value will be used to sort the results of this
     * client when used for auto completion.
     */
    void setCompletionWeight(int weight);

    /*!
     * Returns the completion weight of this client.
     */
    [[nodiscard]] int completionWeight() const;

    /*!
     * Sets the LDAP \a server information that shall be
     * used by this client.
     */
    void setServer(const KLDAPCore::LdapServer &server);

    /*!
     * Returns the ldap server information that are used
     * by this client.
     */
    const KLDAPCore::LdapServer server() const;

    /*!
     * Sets the LDAP \a attributes that should be returned
     * in the query result.
     *
     * Pass an empty list to include all available attributes.
     */
    void setAttributes(const QStringList &attributes);

    /*!
     * Returns the LDAP attributes that should be returned
     * in the query result.
     */
    [[nodiscard]] QStringList attributes() const;

    /*!
     * Sets the \a scope of the LDAP query.
     *
     * Valid values are 'one' or 'sub'.
     */
    void setScope(const QString &scope);

    /*!
     * Starts the query with the given \a filter.
     */
    void startQuery(const QString &filter);

    /*!
     * Cancels a running query.
     */
    void cancelQuery();

Q_SIGNALS:
    /*!
     * This signal is emitted when the query has finished.
     */
    void done();

    /*!
     * This signal is emitted in case of an error.
     *
     * \a message A message that describes the error.
     */
    void error(const QString &message);

    /*!
     * This signal is emitted once for each object that is
     * returned from the query
     */
    void result(const KLDAPCore::LdapClient &client, const KLDAPCore::LdapObject &);

private:
    class LdapClientPrivate;
    std::unique_ptr<LdapClientPrivate> const d;
};
}
