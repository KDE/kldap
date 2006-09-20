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

#ifndef KLDAP_LDAPSEARCH_H
#define KLDAP_LDAPSEARCH_H

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QList>
#include <QtCore/QByteArray>

#include <kldap/ldapurl.h>
#include <kldap/ldapobject.h>
#include <kldap/ldapcontrol.h>
#include <kldap/ldapserver.h>
#include <kldap/ldapconnection.h>
#include <kldap/ldapoperation.h>

#include <kldap/kldap.h>

namespace KLDAP {

  /** This class starts a search operation on a LDAP server and returns the
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
       * Constructs an LdapConnection object with the given connection. If this form
       * of constructor used, then always this connection will be used regardless of the
       * LDAP Url or LdapServer object passed to search().
       */
      LdapSearch( LdapConnection &connection );

      virtual ~LdapSearch();

      /**
       * Sets the client controls which will sent with each operation.
       */
      void setClientControls( const LdapControls &ctrls );
      /**
       * Sets the server controls which will sent with each operation.
       */
      void setServerControls( const LdapControls &ctrls );
      /**
       * Starts a search operation on the LDAP server @param server, with the given scope and
       * returning the attributes specified with @param attributes.
       */
      bool search( const LdapServer &server, LdapUrl::Scope scope = LdapUrl::Sub, 
        const QStringList& attributes = QStringList() );
      /**
       * Starts a search operation on the given LDAP URL.
       */
      bool search( const LdapUrl &url );
      /**
       * Starts a search operation if the LdapConnection object already set in the constructor
       */
      bool search( const QString &base, 
        LdapUrl::Scope scope = LdapUrl::Sub,
        const QString &filter = QString(), 
        const QStringList& attributes = QStringList(),
        int pagesize = 0 );

    Q_SIGNALS:
      /**
       * Emitted for each result object.
       */
      void data( const LdapObject& );
      /**
       * Emitted when the searching finished.
       */
      void done();
      /**
       * Emitted when an LDAP error occurred.
       */
      void error( int, QString );

    private Q_SLOTS:
      void result();
    private:
      void closeConnection();
      bool startSearch( const QString &base, LdapUrl::Scope scope, 
        const QString &filter, const QStringList& attributes, int pagesize );
      
      class LdapSearchPrivate;
      LdapSearchPrivate* const d;
  };

}
#endif
