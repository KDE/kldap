/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kldap_core_export.h"
#include "ldapconnection.h"
#include "ldapcontrol.h"
#include "ldapdn.h"
#include "ldapobject.h"
#include "ldapurl.h"

#include <QByteArray>
#include <QList>
#include <QString>

#include <memory>

namespace KLDAPCore
{
/*!
 * \brief
 * This class allows sending an ldap operation
 * (search, rename, modify, delete, compare, exop) to an LDAP server.
 */
class KLDAP_CORE_EXPORT LdapOperation
{
public:
    using ModType = enum {
        Mod_None,
        Mod_Add,
        Mod_Replace,
        Mod_Del,
    };

    using ResultType = enum {
        RES_BIND = 0x61,
        RES_SEARCH_ENTRY = 0x64,
        RES_SEARCH_REFERENCE = 0x73,
        RES_SEARCH_RESULT = 0x65,
        RES_MODIFY = 0x67,
        RES_ADD = 0x69,
        RES_DELETE = 0x69,
        RES_MODDN = 0x6d,
        RES_COMPARE = 0x6f,
        RES_EXTENDED = 0x78,
        RES_EXTENDED_PARTIAL = 0x79,
    };

    using ModOp = struct {
        ModType type;
        QString attr;
        QList<QByteArray> values;
    };

    using ModOps = QList<ModOp>;

    enum SASL_Fields {
        SASL_Authname = 0x1,
        SASL_Authzid = 0x2,
        SASL_Realm = 0x4,
        SASL_Password = 0x8,
    };

    struct SASL_Credentials {
        int fields;
        QString authname;
        QString authzid;
        QString realm;
        QString password;
    };

    using SASL_Callback_Proc = int(SASL_Credentials &, void *);

    struct SASL_Data {
        SASL_Callback_Proc *proc;
        void *data;
        SASL_Credentials creds;
    };

    LdapOperation();

    /*!
     * Constructs an LdapOperation with the given LDAP connection.
     * Without a living connection object, LDAP operations are not possible.
     * \param conn the LDAP connection to use
     */
    explicit LdapOperation(LdapConnection &conn);

    /*!
     * Destroys the LdapOperation object.
     */
    ~LdapOperation();

    /*!
     * Sets the connection object to use for LDAP operations.
     * Without a living connection object, LDAP operations are not possible.
     * \param conn the connection object to set
     */
    void setConnection(LdapConnection &conn);

    /*!
     * Returns the connection object being used.
     * \return the LDAP connection object
     */
    LdapConnection &connection();

    /*!
     * Sets the client controls which will be sent with each operation.
     * \param ctrls the controls to set
     */
    void setClientControls(const LdapControls &ctrls);

    /*!
     * Sets the server controls which will be sent with each operation.
     * \param ctrls the controls to set
     */
    void setServerControls(const LdapControls &ctrls);

    /*!
     * Returns the client controls (which were set by setClientControls()).
     * \return the list of client controls
     */
    [[nodiscard]] LdapControls clientControls() const;

    /*!
     * Returns the server controls (which were set by setServerControls()).
     * \return the list of server controls
     */
    [[nodiscard]] LdapControls serverControls() const;

    /*!
     * Starts an asynchronous bind operation to the server specified in the connection object.
     * Can do simple or SASL bind. Returns a message id if successful, negative value if not.
     * \param creds optional credentials for the bind
     * \param saslproc optional SASL callback procedure
     * \param data optional data for the SASL callback
     * \return the message ID if successful, negative value if not
     */
    [[nodiscard]] int bind(const QByteArray &creds = QByteArray(), SASL_Callback_Proc *saslproc = nullptr, void *data = nullptr);

    /*!
     * Performs a synchronous bind operation to the server.
     * Can do simple or SASL bind.
     * \param saslproc optional SASL callback procedure
     * \param data optional data for the SASL callback
     * \return KLDAP_SUCCESS if successful, else an LDAP error code
     */
    [[nodiscard]] int bind_s(SASL_Callback_Proc *saslproc = nullptr, void *data = nullptr);

    /*!
     * Starts an asynchronous search operation.
     * \param base the base DN for the search
     * \param scope the search scope
     * \param filter the LDAP filter string
     * \param attrs the list of attributes to retrieve
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int search(const LdapDN &base, LdapUrl::Scope scope, const QString &filter, const QStringList &attrs);

    /*!
     * Starts an asynchronous add operation.
     * \param object the LDAP object to add
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int add(const LdapObject &object);

    /*!
     * Performs a synchronous add operation.
     * \param object the LDAP object to add to the database
     * \return KLDAP_SUCCESS if successful, else an LDAP error code
     */
    [[nodiscard]] int add_s(const LdapObject &object);

    /*!
     * Starts an asynchronous add operation using ModOps.
     * \param dn the DN to add
     * \param ops the list of modification operations
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int add(const LdapDN &dn, const ModOps &ops);

    /*!
     * Performs a synchronous add operation using ModOps.
     * \param dn the DN to add
     * \param ops the list of modification operations
     * \return KLDAP_SUCCESS if successful, else an LDAP error code
     */
    [[nodiscard]] int add_s(const LdapDN &dn, const ModOps &ops);

    /*!
     * Starts an asynchronous rename operation (modrdn).
     * \param dn the DN to rename
     * \param newRdn the new relative DN
     * \param newSuperior the new parent DN (empty to keep parent)
     * \param deleteold whether to delete the old DN
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int rename(const LdapDN &dn, const QString &newRdn, const QString &newSuperior, bool deleteold = true);

    /*!
     * Performs a synchronous rename operation (modrdn).
     * \param dn the DN to rename
     * \param newRdn the new relative DN
     * \param newSuperior the new parent DN (empty to keep parent)
     * \param deleteold whether to delete the old DN
     * \return KLDAP_SUCCESS if successful, else an LDAP error code
     */
    [[nodiscard]] int rename_s(const LdapDN &dn, const QString &newRdn, const QString &newSuperior, bool deleteold = true);

    /*!
     * Starts an asynchronous delete operation.
     * \param dn the DN to delete
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int del(const LdapDN &dn);

    /*!
     * Performs a synchronous delete operation.
     * \param dn the DN to delete
     * \return KLDAP_SUCCESS if successful, else an LDAP error code
     */
    [[nodiscard]] int del_s(const LdapDN &dn);

    /*!
     * Starts an asynchronous modify operation.
     * \param dn the DN to modify
     * \param ops the list of modification operations
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int modify(const LdapDN &dn, const ModOps &ops);

    /*!
     * Performs a synchronous modify operation.
     * \param dn the DN to modify
     * \param ops the list of modification operations
     * \return KLDAP_SUCCESS if successful, else an LDAP error code
     */
    [[nodiscard]] int modify_s(const LdapDN &dn, const ModOps &ops);

    /*!
     * Starts an asynchronous compare operation.
     * \param dn the DN to compare
     * \param attr the attribute name to compare
     * \param value the value to compare with
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int compare(const LdapDN &dn, const QString &attr, const QByteArray &value);

    /*!
     * Performs a synchronous compare operation.
     * \param dn the DN to compare
     * \param attr the attribute name to compare
     * \param value the value to compare with
     * \return KLDAP_COMPARE_TRUE if the entry contains the attribute value,
     *         KLDAP_COMPARE_FALSE if it does not, or an LDAP error code
     */
    [[nodiscard]] int compare_s(const LdapDN &dn, const QString &attr, const QByteArray &value);

    /*!
     * Starts an asynchronous extended operation.
     * \param oid the OID of the extended operation
     * \param data the data for the extended operation
     * \return a message id if successful, -1 if not
     */
    [[nodiscard]] int exop(const QString &oid, const QByteArray &data);

    /*!
     * Performs a synchronous extended operation.
     * \param oid the OID of the extended operation
     * \param data the data for the extended operation
     * \return KLDAP_SUCCESS if successful, else an LDAP error code
     */
    [[nodiscard]] int exop_s(const QString &oid, const QByteArray &data);

    /*!
     * Abandons a long-running operation.
     * \param id the message id of the operation to abandon
     * \return 0 on success, -1 on error
     */
    int abandon(int id);

    /*!
     * Waits for a result message from the LDAP server.
     * If msecs is -1, this function will block indefinitely.
     * If msecs is 0, this function will return immediately (poll).
     *
     * Returns the type of the result LDAP message (RES_XXX constants).
     * -1 if an error occurred, 0 if the timeout value elapsed.
     * Note: Return code -1 means fetching the message resulted in error,
     * not the LDAP operation error. Call connection().ldapErrorCode() to
     * determine if the operation succeeded.
     * \param id the message id to wait for
     * \param msecs timeout in milliseconds (-1 for infinite)
     * \return the result type, 0 on timeout, -1 on error
     */
    [[nodiscard]] int waitForResult(int id, int msecs = -1);

    /*!
     * Returns the result object if result() returned RES_SEARCH_ENTRY.
     * \return the LDAP result object
     */
    [[nodiscard]] LdapObject object() const;

    /*!
     * Returns the result object controls from the returned LDAP message.
     * \return the list of controls
     */
    [[nodiscard]] LdapControls controls() const;

    /*!
     * Returns the OID of the extended operation response.
     * \return the OID of the extended operation
     */
    [[nodiscard]] QByteArray extendedOid() const;

    /*!
     * Returns the data from the extended operation response.
     * \return the extended operation data
     */
    [[nodiscard]] QByteArray extendedData() const;

    /*!
     * Returns the matched DN string from the message.
     * The server might supply this indicating how much of a name in a request was recognized.
     * \return the matched DN
     */
    [[nodiscard]] QString matchedDn() const;

    /*!
     * Returns the referral strings from the parsed message (if any).
     * \return the list of referral strings
     */
    [[nodiscard]] QList<QByteArray> referrals() const;

    /*!
     * Returns the server response for a bind request.
     * (result returned RES_BIND)
     * \return the server credentials
     */
    [[nodiscard]] QByteArray serverCred() const;

private:
    class LdapOperationPrivate;
    std::unique_ptr<LdapOperationPrivate> const d;

    Q_DISABLE_COPY(LdapOperation)
};
}
