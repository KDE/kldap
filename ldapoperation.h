/*
  This file is part of libkldap.
  Copyright (c) 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General  Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; see the file COPYING.LIB.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#ifndef KLDAP_LDAPOPERATION_H
#define KLDAP_LDAPOPERATION_H

#include "kldap_export.h"
#include "ldapconnection.h"
#include "ldapcontrol.h"
#include "ldapobject.h"
#include "ldapdn.h"
#include "ldapserver.h"
#include "ldapurl.h"

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QString>

namespace KLDAP {

/**
 * @brief
 * This class allows sending an ldap operation
 * (search, rename, modify, delete, compare, exop) to an LDAP server.
 */
class KLDAP_EXPORT LdapOperation
{
  public:
    typedef enum {
      Mod_None, Mod_Add, Mod_Replace, Mod_Del
    } ModType;

    typedef enum {
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
      RES_EXTENDED_PARTIAL = 0x79
    } ResultType;

    typedef struct {
      ModType type;
      QString attr;
      QList<QByteArray> values;
    } ModOp ;

    typedef QList<ModOp> ModOps;

    enum SASL_Fields {
      SASL_Authname = 0x1,
      SASL_Authzid = 0x2,
      SASL_Realm = 0x4,
      SASL_Password = 0x8
    };

    struct SASL_Credentials {
      int fields;
      QString authname;
      QString authzid;
      QString realm;
      QString password;
    };

    typedef int (SASL_Callback_Proc) ( SASL_Credentials &cred, void *data );

    struct SASL_Data {
      SASL_Callback_Proc *proc;
      void *data;
      SASL_Credentials creds;
    };

    LdapOperation();
    LdapOperation( LdapConnection &conn );
    virtual ~LdapOperation();

    /**
     * Sets the connection object. Without living connection object,
     * LDAP operations are not possible.
     */
    void setConnection( LdapConnection &conn );
    /**
     * Returns the connection object.
     */
    LdapConnection &connection();
    /**
     * Sets the client controls which will sent with each operation.
     */
    void setClientControls( const LdapControls &ctrls );
    /**
     * Sets the server controls which will sent with each operation.
     */
    void setServerControls( const LdapControls &ctrls );
    /**
     * Returns the client controls (which set by setClientControls()).
     */
    LdapControls clientControls() const;
    /**
     * Returns the server controls (which set by setServerControls()).
     */
    LdapControls serverControls() const;

    /**
     * Binds to the server which specified in the connection object.
     * Can do simple or SASL bind. Returns a message id if successful, negative value if not.
     */
    int bind( const QByteArray &creds = QByteArray(),
              SASL_Callback_Proc *saslproc = NULL, void *data = NULL );

    /**
     * Binds to the server which specified in the connection object.
     * Can do simple or SASL bind. This is the synchronous version.
     * Returns KLDAP_SUCCESS id if successful, else an LDAP error code.
     */
    int bind_s( SASL_Callback_Proc *saslproc = NULL, void *data = NULL );

    /**
     * Starts a search operation with the given base DN, scope, filter and
     * result attributes. Returns a message id if successful, -1 if not.
     */
    int search( const LdapDN &base, LdapUrl::Scope scope,
                const QString &filter, const QStringList &attrs );
    /**
     * Starts an addition operation.
     * Returns a message id if successful, -1 if not.
     */
    int add( const LdapObject &object );
    /**
     * Adds the specified object to the LDAP database.
     * Returns KLDAP_SUCCESS id if successful, else an LDAP error code.
     */
    int add_s( const LdapObject &object );
    /**
     * Starts an addition operation. This version accepts ModOps not LdapObject.
     * Returns a message id if successful, -1 if not.
     */
    int add( const LdapDN &dn, const ModOps &ops );
    /**
     * Adds the specified object to the LDAP database. This version accepts ModOps not LdapObject.
     * This is the synchronous version.
     * Returns KLDAP_SUCCESS id if successful, else an LDAP error code.
     */
    int add_s( const LdapDN &dn, const ModOps &ops );
    /**
     * Starts a modrdn operation on given DN, changing its RDN to newRdn,
     * changing its parent to newSuperior (if it's not empty), and deletes
     * the old dn if deleteold is true.
     * Returns a message id if successful, -1 if not.
     */
    int rename( const LdapDN &dn, const QString &newRdn,
                const QString &newSuperior, bool deleteold = true );
    /**
     * Performs a modrdn operation on given DN, changing its RDN to newRdn,
     * changing its parent to newSuperior (if it's not empty), and deletes
     * the old dn if deleteold is true. This is the synchronous version.
     * Returns KLDAP_SUCCESS id if successful, else an LDAP error code.
     */
    int rename_s( const LdapDN &dn, const QString &newRdn,
                  const QString &newSuperior, bool deleteold = true );
    /**
     * Starts a delete operation on the given DN.
     * Returns a message id if successful, -1 if not.
     */
    int del( const LdapDN &dn );
    /**
     * Deletes the given DN. This is the synchronous version.
     * Returns KLDAP_SUCCESS id if successful, else an LDAP error code.
     */
    int del_s( const LdapDN &dn );
    /**
     * Starts a modify operation on the given DN.
     * Returns a message id if successful, -1 if not.
     */
    int modify( const LdapDN &dn, const ModOps &ops );
    /**
     * Performs a modify operation on the given DN.
     * This is the synchronous version.
     * Returns KLDAP_SUCCESS id if successful, else an LDAP error code.
     */
    int modify_s( const LdapDN &dn, const ModOps &ops );
    /**
     * Starts a compare operation on the given DN, compares the specified
     * attribute with the given value.
     * Returns a message id if successful, -1 if not.
     */
    int compare( const LdapDN &dn, const QString &attr, const QByteArray &value );
    /**
     * Performs a compare operation on the given DN, compares the specified
     * attribute with the given value. This is the synchronous version.
     * Returns KLDAP_COMPARE_TRUE if the entry contains the attribute value
     * and KLDAP_COMPARE_FALSE if it does not. Otherwise, some error code
     * is returned.
     */
    int compare_s( const LdapDN &dn, const QString &attr, const QByteArray &value );
    /**
     * Starts an extended operation specified with oid and data.
     * Returns a message id if successful, -1 if not.
     */
    int exop( const QString &oid, const QByteArray &data );
    /**
     * Performs an extended operation specified with oid and data.
     * This is the synchronous version.
     * Returns KLDAP_SUCCESS id if successful, else an LDAP error code.
     */
    int exop_s( const QString &oid, const QByteArray &data );
    /**
     * Abandons a long-running operation. Requires the message id.
     */
    int abandon( int id );
    /**
     * Waits for up to \p msecs milliseconds for a result message from the LDAP
     * server. If \p msecs is -1, then this function will block indefinitely.
     * If \p msecs is 0, then this function will return immediately, that is it
     * will perform a poll for a result message.
     *
     * Returns the type of the result LDAP message (RES_XXX constants).
     * -1 if error occurred, 0 if the timeout value elapsed. Note!
     * Return code -1 means that fetching the message resulted in error,
     * not the LDAP operation error. Call connection().ldapErrorCode() to
     * determine if the operation succeeded.
     */
    int waitForResult( int id, int msecs = -1 );
    /**
     * Returns the result object if result() returned RES_SEARCH_ENTRY.
     */
    LdapObject object() const;
    /**
     * Returns the server controls from the returned ldap message (grabbed
     * by result()).
     */
    LdapControls controls() const;
    /**
     * Returns the OID of the extended operation response (result
     * returned RES_EXTENDED).
     */
    QByteArray extendedOid() const;
    /**
     * Returns the data from the extended operation response (result
     * returned RES_EXTENDED).
     */
    QByteArray extendedData() const;
    /**
     * The server might supply a matched DN string in the message indicating
     * how much of a name in a request was recognized. This can be grabbed by
     * matchedDn().
     */
    QString matchedDn() const;
    /**
     * This function returns the referral strings from the parsed message
     * (if any).
     */
    QList<QByteArray> referrals() const;
    /**
     * Returns the server response for a bind request (result
     * returned RES_BIND).
     */
    QByteArray serverCred() const;

  private:
    class LdapOperationPrivate;
    LdapOperationPrivate *const d;

    Q_DISABLE_COPY( LdapOperation )
};

}

#endif
