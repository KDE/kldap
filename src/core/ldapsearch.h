/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QObject>
#include <QString>
class LdapSearchPrivate;

#include "kldap_core_export.h"

#include "ldapconnection.h"
#include "ldapcontrol.h"
#include "ldapobject.h"
#include "ldapoperation.h"
#include "ldapserver.h"
#include "ldapurl.h"

// clazy:excludeall=ctor-missing-parent-argument

namespace KLDAPCore
{
/*!
 * \class KLDAPCore::LdapSearch
 * \inmodule LdapCore
 * \inheaderfile KLDAPCore/LdapSearch
 *
 * \brief
 * This class starts a search operation on a LDAP server and returns the
 * search values via a Qt signal.
 */
class KLDAP_CORE_EXPORT LdapSearch : public QObject
{
    Q_OBJECT

public:
    /*!
     * Constructs an LdapSearch object.
     */
    LdapSearch();

    /*!
     * Constructs an LdapConnection object with the given connection.
     * If this form of constructor is used, then always this connection will be used
     * regardless of the LDAP URL or LdapServer object passed to search().
     * \param connection the connection used to construct LdapConnection object
     */
    explicit LdapSearch(LdapConnection &connection);

    /*!
     * Destroys the LdapSearch object.
     */
    ~LdapSearch() override;

    /*!
     * Sets the connection for this object to use for searches from now
     * onwards, regardless of the LDAP URL or LdapServer object passed to
     * search().
     * \param connection the connection to use for searches
     */
    void setConnection(LdapConnection &connection);

    /*!
     * Sets the client controls which will be sent with each operation.
     * \param ctrls the LDAP controls to set
     */
    void setClientControls(const LdapControls &ctrls);

    /*!
     * Sets the server controls which will be sent with each operation.
     * \param ctrls the LDAP controls to set
     */
    void setServerControls(const LdapControls &ctrls);

    /*!
     * Starts a search operation on the given LDAP server,
     * returning the attributes specified.
     * \param server the LDAP server to search on
     * \param attributes the list of attributes to retrieve
     * \param count how many entries to list. If it's >0, then result()
     *              will be emitted when the number of entries is reached, but with
     *              isFinished() set to false
     * \return true if the search started successfully, false otherwise
     */
    [[nodiscard]] bool search(const LdapServer &server, const QStringList &attributes = QStringList(), int count = 0);

    /*!
     * Starts a search operation on the given LDAP URL.
     * \param url the LDAP URL to search on
     * \param count how many entries to list
     * \return true if the search started successfully, false otherwise
     */
    [[nodiscard]] bool search(const LdapUrl &url, int count = 0);

    /*!
     * Starts a search operation if the LdapConnection object was already set
     * in the constructor.
     * \param base the base DN for the search
     * \param scope the scope of the search
     * \param filter the LDAP filter string
     * \param attributes the list of attributes to retrieve
     * \param pagesize the page size for paged results
     * \param count how many entries to list
     * \return true if the search started successfully, false otherwise
     */
    [[nodiscard]] bool search(const LdapDN &base,
                              LdapUrl::Scope scope = LdapUrl::Sub,
                              const QString &filter = QString(),
                              const QStringList &attributes = QStringList(),
                              int pagesize = 0,
                              int count = 0);

    /*!
     * Continues the search (if you set count to non-zero in search(), and isFinished() is false).
     */
    void continueSearch();

    /*!
     * Returns true if the search is finished, false otherwise.
     * \return true if the search has finished
     */
    [[nodiscard]] bool isFinished() const;

    /*!
     * Tries to abandon the search.
     */
    void abandon();

    /*!
     * Returns the error code of the search operation (0 if no error).
     * \return the LDAP error code
     */
    [[nodiscard]] int error() const;

    /*!
     * Returns the error description of the search operation.
     * \return the error description string
     */
    [[nodiscard]] QString errorString() const;

Q_SIGNALS:
    /*!
     * Emitted for each result object.
     */
    void data(KLDAPCore::LdapSearch *search, const KLDAPCore::LdapObject &obj);

    /*!
     * Emitted when the searching finished.
     */
    void result(KLDAPCore::LdapSearch *search);

private:
    std::unique_ptr<LdapSearchPrivate> const d;
    Q_DISABLE_COPY(LdapSearch)
};
}
