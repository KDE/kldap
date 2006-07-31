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

#include <QString>
#include <QList>
#include <QByteArray>

#include <ldapurl.h>
#include <ldapobject.h>
#include <ldapcontrol.h>
#include <ldapserver.h>
#include <ldapconnection.h>

#include <kldap.h>

namespace KLDAP {

  /** This class allows sending an ldap operation 
   * (search, rename, modify, delete) to an LDAP server.
   */
  class KLDAP_EXPORT LdapOperation
  {
    public:
      typedef enum ModType{ Mod_Add, Mod_Replace, Mod_Del };
      typedef enum ResultType {
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
      };

      typedef struct ModOp {
        ModType type;
        QString attr;
        QList<QByteArray> values;
      };

      typedef QList<ModOp> ModOps;

      LdapOperation();
      LdapOperation( const LdapConnection &conn );
      virtual ~LdapOperation();

      void setConnection( const LdapConnection &conn );
      void setClientControls( const LdapControls &ctrls ) { mClientCtrls = ctrls; }
      void setServerControls( const LdapControls &ctrls ) { mServerCtrls = ctrls; }
      const LdapControls &clientControls() const { return mClientCtrls; }
      const LdapControls &serverControls() const { return mServerCtrls; }

      int search( const QString &base, LdapUrl::Scope scope, 
        const QString &filter, const QStringList& attrs );
      int rename( const QString &dn, const QString &newRdn, 
        const QString &newSuperior, bool deleteold = true );
      int del( const QString &dn );
      int modify( const QString &dn, const ModOps &ops );
      int compare( const QString &dn, const QString &attr, const QByteArray &value );
      int exop( const QString &oid, const QByteArray &data );
      int abandon( int id );
      
      /** Returns the type of the result LDAP message (RES_XXX constants). -1 if error occured. */
      int result( int id );
      /** Returns the result object if result() returned RES_SEARCH_ENTRY */
      const LdapObject &object() const { return mObject; }
      /** Returns the server controls from the returned ldap message (grabbed by result()) */
      const LdapControls &controls() const { return mControls; }

    private:

      LdapControls mClientCtrls,mServerCtrls, mControls;
      LdapObject mObject;

      const LdapConnection *mConnection;

      class LdapOperationPrivate;
      LdapOperationPrivate *d;

  };

}
#endif
