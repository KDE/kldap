/*
  This file is part of libkldap.
  Copyright (c) 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
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

#ifndef KLDAP_LDAPCONFIGWIDGET_H
#define KLDAP_LDAPCONFIGWIDGET_H

#include <QtCore/QString>
#include <QtGui/QWidget>

#include "ldapdn.h"
#include "kldap_export.h"
#include "ldapobject.h"
#include "ldapserver.h"
#include "ldapurl.h"

namespace KLDAP {

class LdapSearch;

/**
  @brief LDAP Configuration widget

  This class can be used to query the user for LDAP connection parameters.
  It's KConfigXT compatible, using widget names starting with kcfg_
*/

class KLDAP_EXPORT LdapConfigWidget : public QWidget
{
  Q_OBJECT
  Q_FLAGS( WinFlags )
  Q_ENUMS( Security )
  Q_ENUMS( Auth )
  Q_PROPERTY( WinFlags features READ features WRITE setFeatures )
  Q_PROPERTY( QString user READ user WRITE setUser )
  Q_PROPERTY( QString bindDn READ bindDn WRITE setBindDn )
  Q_PROPERTY( QString realm READ realm WRITE setRealm )
  Q_PROPERTY( QString password READ password WRITE setPassword )
  Q_PROPERTY( QString host READ host WRITE setHost )
  Q_PROPERTY( int port READ port WRITE setPort )
  Q_PROPERTY( int version READ version WRITE setVersion )
  Q_PROPERTY( LdapDN dn READ dn WRITE setDn )
  Q_PROPERTY( QString filter READ filter WRITE setFilter )
  Q_PROPERTY( QString mech READ mech WRITE setMech )
  Q_PROPERTY( Security security READ security WRITE setSecurity )
  Q_PROPERTY( Auth auth READ auth WRITE setAuth )
  Q_PROPERTY( int sizeLimit READ sizeLimit WRITE setSizeLimit )
  Q_PROPERTY( int timeLimit READ timeLimit WRITE setTimeLimit )
  Q_PROPERTY( int pageSize READ pageSize WRITE setPageSize )

  public:

    enum WinFlag {
      W_USER = 0x1,
      W_BINDDN = 0x2,
      W_REALM = 0x4,
      W_PASS = 0x8,
      W_HOST = 0x10,
      W_PORT = 0x20,
      W_VER = 0x40,
      W_DN = 0x80,
      W_FILTER = 0x100,
      W_SECBOX = 0x200,
      W_AUTHBOX = 0x400,
      W_TIMELIMIT = 0x800,
      W_SIZELIMIT = 0x1000,
      W_PAGESIZE = 0x2000,
      W_ALL = 0x2fff
    };

    typedef enum {
      None, SSL, TLS
    } Security;
    typedef enum {
      Anonymous, Simple, SASL
    } Auth;

    Q_DECLARE_FLAGS( WinFlags, WinFlag )

    /** Constructs an empty configuration widget.
     * You need to call setFlags() after this.
     */
    explicit LdapConfigWidget( QWidget *parent = 0, Qt::WFlags fl = 0 );
    /** Constructs a configuration widget */
    explicit LdapConfigWidget( WinFlags flags, QWidget *parent = 0,
                               Qt::WFlags fl = 0 );
    /** Destructs a configuration widget */
    virtual ~LdapConfigWidget();

    /** Sets the user name. Kconfig widget name: kcfg_ldapuser */
    void setUser( const QString &user );
    /** Gets the user name. Kconfig widget name: kcfg_ldapuser */
    QString user() const;

    /** Sets the password. Kconfig widget name: kcfg_ldappassword */
    void setPassword( const QString &password );
    /** Gets the password. Kconfig widget name: kcfg_ldappassword */
    QString password() const;

    /**
     * Sets the bind dn.
     * Kconfig widget name: kcfg_ldapbinddn
     */
    void setBindDn( const QString &binddn );
    /** Gets the bind dn. Kconfig widget name: kcfg_ldapbinddn*/
    QString bindDn() const;

    /** Sets the SASL realm. Kconfig widget name: kcfg_ldaprealm */
    void setRealm( const QString &realm );
    /** Gets the SASL realm. Kconfig widget name: kcfg_ldaprealm */
    QString realm() const;

    /** Sets the host name. Kconfig widget name: kcfg_ldaphost */
    void setHost( const QString &host );
    /** Gets the host name. Kconfig widget name: kcfg_ldaphost */
    QString host() const;

    /** Sets the LDAP port. Kconfig widget name: kcfg_ldapport */
    void setPort( int port );
    /** Gets the LDAP port. Kconfig widget name: kcfg_ldapport */
    int port() const;

    /** Sets the LDAP protocol version. Kconfig widget name: kcfg_ldapver */
    void setVersion( int version );
    /** Gets the LDAP protocol version. Kconfig widget name: kcfg_ldapver */
    int version() const;

    /** Sets the LDAP Base DN. Kconfig widget name: kcfg_ldapdn */
    void setDn( const LdapDN &dn );
    /** Gets the LDAP Base DN. Kconfig widget name: kcfg_ldapdn */
    LdapDN dn() const;

    /** Sets the LDAP Filter. Kconfig widget name: kcfg_ldapfilter */
    void setFilter( const QString &filter );
    /** Gets the LDAP Filter. Kconfig widget name: kcfg_ldapfilter */
    QString filter() const;

    /** Sets the SASL Mechanism. Kconfig widget name: kcfg_ldapsaslmech */
    void setMech( const QString &mech );
    /** Gets the SASL Mechanism. Kconfig widget name: kcfg_ldapsaslmech */
    QString mech() const;

    /**
     * Sets the security type (None, SSL, TLS).
     * Kconfig widget names: kcfg_ldapnosec, kcfg_ldaptls, kcfg_ldapssl
     */
    void setSecurity( Security security );
    /**
     * Returns the security type.
     * Kconfig widget names: kcfg_ldapnosec, kcfg_ldaptls, kcfg_ldapssl
     */
    Security security() const;

    /**
     * Sets the authentication type (Anonymous, Simple, SASL).
     * Kconfig widget names: kcfg_ldapanon, kcfg_ldapsimple, kcfg_ldapsasl
     */
    void setAuth( Auth auth );
    /**
     * Returns the authentication type.
     * Kconfig widget names: kcfg_ldapanon, kcfg_ldapsimple, kcfg_ldapsasl
     */
    Auth auth() const;

    /**
     * Sets the size limit.
     * KConfig widget name: kcfg_ldapsizelimit
     */
    void setSizeLimit( int sizelimit );
    /**
     * Returns the size limit.
     * KConfig widget name: kcfg_ldapsizelimit
     */
    int sizeLimit() const;

    /**
     * Sets the time limit.
     * KConfig widget name: kcfg_ldaptimelimit
     */
    void setTimeLimit( int timelimit );
    /**
     * Returns the time limit.
     * KConfig widget name: kcfg_ldaptimelimit
     */
    int timeLimit() const;

    /**
     * Sets the page size.
     * KConfig widget name: kcfg_ldappagesize
     */
    void setPageSize( int pagesize );
    /**
     * Returns the page size.
     * KConfig widget name: kcfg_ldappagesize
     */
    int pageSize() const;

    WinFlags features() const;
    void setFeatures( WinFlags features );

    /**
     * Returns a LDAP Url constructed from the settings given.
     * Extensions are filled for use in the LDAP ioslave
     */
    LdapUrl url() const;
    /**
     * Set up the widget via an LDAP Url.
     */
    void setUrl( const LdapUrl &url );

    /**
     * Returns an LdapServer object constructed from the settings given.
     */
    LdapServer server() const;
    /**
     * Set up the widget via an LdapServer object.
     */
    void setServer( const LdapServer &server );

  private:
    class Private;
    Private *const d;

    Q_PRIVATE_SLOT( d, void setLDAPPort() )
    Q_PRIVATE_SLOT( d, void setLDAPSPort() )
    Q_PRIVATE_SLOT( d, void setAnonymous( bool ) )
    Q_PRIVATE_SLOT( d, void setSimple( bool ) )
    Q_PRIVATE_SLOT( d, void setSASL( bool ) )
    Q_PRIVATE_SLOT( d, void queryDNClicked() )
    Q_PRIVATE_SLOT( d, void queryMechClicked() )
    Q_PRIVATE_SLOT( d, void loadData( KLDAP::LdapSearch*, const KLDAP::LdapObject& ) )
    Q_PRIVATE_SLOT( d, void loadResult( KLDAP::LdapSearch* ) )
};

Q_DECLARE_OPERATORS_FOR_FLAGS( LdapConfigWidget::WinFlags )

}

#endif
