/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#ifndef KLDAP_LDAPSEARCH_H
#define KLDAP_LDAPSEARCH_H

#include <QObject>
#include <QString>
class LdapSearchPrivate;

#include "kldap_export.h"

#include "ldapconnection.h"
#include "ldapcontrol.h"
#include "ldapobject.h"
#include "ldapoperation.h"
#include "ldapserver.h"
#include "ldapurl.h"

// clazy:excludeall=ctor-missing-parent-argument

namespace KLDAP {
/**
 * @brief
 * This class starts a search operation on a LDAP server and returns the
 * search values via a Qt signal.
 */
class KLDAP_EXPORT LdapSearch : public QObject
{
    Q_OBJECT

public:
    /**
     * Constructs an LdapSearch object
     */
    LdapSearch();

    /**
     * Constructs an LdapConnection object with the given connection. If this
     * form of constructor used, then always this connection will be used
     * regardless of the LDAP Url or LdapServer object passed to search().
     * @param connection the connection used to construct LdapConnection object
     */
    explicit LdapSearch(LdapConnection &connection);

    ~LdapSearch();

    /**
     * Sets the connection for this object to use for searches from now
     * onwards, regardless of the LDAP Url or LdapServer object passed to
     * search().
     */
    void setConnection(LdapConnection &connection);

    /**
     * Sets the client controls which will sent with each operation.
     */
    void setClientControls(const LdapControls &ctrls);

    /**
     * Sets the server controls which will sent with each operation.
     */
    void setServerControls(const LdapControls &ctrls);

    /**
     * Starts a search operation on the LDAP server @param server,
     * returning the attributes specified with @param attributes.
     * @param count means how many entries to list. If it's >0, then result()
     * will be emitted when the number of entries is reached, but with
     * isFinished() set to false.
     */
    Q_REQUIRED_RESULT bool search(const LdapServer &server, const QStringList &attributes = QStringList(), int count = 0);

    /**
     * Starts a search operation on the given LDAP URL.
     */
    Q_REQUIRED_RESULT bool search(const LdapUrl &url, int count = 0);

    /**
     * Starts a search operation if the LdapConnection object already set
     * in the constructor.
     */
    Q_REQUIRED_RESULT bool search(const LdapDN &base, LdapUrl::Scope scope = LdapUrl::Sub, const QString &filter = QString(),
                                  const QStringList &attributes = QStringList(), int pagesize = 0, int count = 0);

    /**
     * Continues the search (if you set count to non-zero in search(), and isFinished() is false)
     */
    void continueSearch();
    /**
     * Returns true if the search is finished else returns false.
     */
    Q_REQUIRED_RESULT bool isFinished();
    /**
     * Tries to abandon the search.
     */
    void abandon();

    /**
     * Returns the error code of the search operation (0 if no error).
     */
    Q_REQUIRED_RESULT int error() const;

    /**
     * Returns the error description of the search operation.
     */
    Q_REQUIRED_RESULT QString errorString() const;

Q_SIGNALS:
    /**
     * Emitted for each result object.
     */
    void data(KLDAP::LdapSearch *search, const KLDAP::LdapObject &obj);

    /**
     * Emitted when the searching finished.
     */
    void result(KLDAP::LdapSearch *search);

private:
    LdapSearchPrivate *const d;
    Q_DISABLE_COPY(LdapSearch)
};
}

#endif
