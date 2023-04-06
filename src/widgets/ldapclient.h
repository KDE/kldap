/* kldapclient.h - LDAP access
 * SPDX-FileCopyrightText: 2002 Klarälvdalens Datakonsult AB
 * SPDX-FileContributor: Steffen Hansen <hansen@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldapwidgets_export.h"
#include <QObject>
#include <QStringList>
#include <memory>

namespace KLDAPCore
{
class LdapObject;
class LdapServer;
}

namespace KLDAPWidgets
{

/**
 * @short An object that represents a configured LDAP server.
 *
 * This class represents a client that to an LDAP server that
 * can be used for LDAP lookups. Every client is identified by
 * a unique numeric id.
 *
 * @since 4.5
 */
class KLDAPWIDGETS_EXPORT LdapClient : public QObject
{
    Q_OBJECT

public:
    /**
     * Creates a new ldap client.
     *
     * @param clientNumber The unique number of this client.
     * @param parent The parent object.
     */
    explicit LdapClient(int clientNumber, QObject *parent = nullptr);

    /**
     * Destroys the ldap client.
     */
    ~LdapClient() override;

    /**
     * Returns the number of this client.
     */
    int clientNumber() const;

    /**
     * Returns whether this client is currently running
     * a search query.
     */
    bool isActive() const;

    /**
     * Sets the completion @p weight of this client.
     *
     * This value will be used to sort the results of this
     * client when used for auto completion.
     */
    void setCompletionWeight(int weight);

    /**
     * Returns the completion weight of this client.
     */
    int completionWeight() const;

    /**
     * Sets the LDAP @p server information that shall be
     * used by this client.
     */
    void setServer(const KLDAPCore::LdapServer &server);

    /**
     * Returns the ldap server information that are used
     * by this client.
     */
    const KLDAPCore::LdapServer server() const;

    /**
     * Sets the LDAP @p attributes that should be returned
     * in the query result.
     *
     * Pass an empty list to include all available attributes.
     */
    void setAttributes(const QStringList &attributes);

    /**
     * Returns the LDAP attributes that should be returned
     * in the query result.
     */
    QStringList attributes() const;

    /**
     * Sets the @p scope of the LDAP query.
     *
     * Valid values are 'one' or 'sub'.
     */
    void setScope(const QString &scope);

    /**
     * Starts the query with the given @p filter.
     */
    void startQuery(const QString &filter);

    /**
     * Cancels a running query.
     */
    void cancelQuery();

Q_SIGNALS:
    /**
     * This signal is emitted when the query has finished.
     */
    void done();

    /**
     * This signal is emitted in case of an error.
     *
     * @param message A message that describes the error.
     */
    void error(const QString &message);

    /**
     * This signal is emitted once for each object that is
     * returned from the query
     */
    void result(const KLDAPWidgets::LdapClient &client, const KLDAPCore::LdapObject &);

private:
    //@cond PRIVATE
    class LdapClientPrivate;
    std::unique_ptr<LdapClientPrivate> const d;
    //@endcond
};
}
