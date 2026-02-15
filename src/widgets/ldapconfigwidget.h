/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QString>
#include <QWidget>

#include "kldapwidgets_export.h"
#include "ldapdn.h"
#include "ldapserver.h"
#include "ldapurl.h"

namespace KLDAPWidgets
{
/*!
  \brief LDAP Configuration widget
  \class KLDAPWidgets::LdapConfigWidget
  \ inmodule LdapWidgets
  \inheaderfile KLDAPWidgets/LdapConfigWidget

  This class can be used to query the user for LDAP connection parameters.
  It's KConfigXT compatible, using widget names starting with kcfg_
*/

class KLDAPWIDGETS_EXPORT LdapConfigWidget : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(WinFlags features READ features WRITE setFeatures)
    Q_PROPERTY(QString user READ user WRITE setUser)
    Q_PROPERTY(QString bindDn READ bindDn WRITE setBindDn)
    Q_PROPERTY(QString realm READ realm WRITE setRealm)
    Q_PROPERTY(QString password READ password WRITE setPassword)
    Q_PROPERTY(QString host READ host WRITE setHost)
    Q_PROPERTY(int port READ port WRITE setPort)
    Q_PROPERTY(int version READ version WRITE setVersion)
    Q_PROPERTY(KLDAPCore::LdapDN dn READ dn WRITE setDn)
    Q_PROPERTY(QString filter READ filter WRITE setFilter)
    Q_PROPERTY(QString mech READ mech WRITE setMech)
    Q_PROPERTY(Security security READ security WRITE setSecurity)
    Q_PROPERTY(Auth auth READ auth WRITE setAuth)
    Q_PROPERTY(int sizeLimit READ sizeLimit WRITE setSizeLimit)
    Q_PROPERTY(int timeLimit READ timeLimit WRITE setTimeLimit)
    Q_PROPERTY(int pageSize READ pageSize WRITE setPageSize)

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
    Q_DECLARE_FLAGS(WinFlags, WinFlag)
    Q_FLAG(WinFlags)

    enum Security {
        None,
        SSL,
        TLS,
    };
    Q_ENUM(Security)

    enum Auth {
        Anonymous,
        Simple,
        SASL,
    };
    Q_ENUM(Auth)

    /*!
     * Constructs an empty configuration widget.
     * You need to call setFeatures() after this.
     * \param parent the parent widget
     * \param fl the window flags to set
     */
    explicit LdapConfigWidget(QWidget *parent = nullptr, Qt::WindowFlags fl = {});

    /*!
     * Constructs a configuration widget with the specified features.
     * \param flags the configuration window flags
     * \param parent the parent widget
     * \param fl the window flags to set
     */
    explicit LdapConfigWidget(WinFlags flags, QWidget *parent = nullptr, Qt::WindowFlags fl = {});

    /*!
     * Destroys the configuration widget.
     */
    ~LdapConfigWidget() override;

    /*!
     * Sets the user name. KConfig widget name: kcfg_ldapuser
     * \param user the user name to set
     */
    void setUser(const QString &user);

    /*!
     * Returns the user name. KConfig widget name: kcfg_ldapuser
     */
    [[nodiscard]] QString user() const;

    /*!
     * Sets the password. KConfig widget name: kcfg_ldappassword
     * \param password the password to set
     */
    void setPassword(const QString &password);

    /*!
     * Returns the password. KConfig widget name: kcfg_ldappassword
     */
    [[nodiscard]] QString password() const;

    /*!
     * Sets the bind DN.
     * KConfig widget name: kcfg_ldapbinddn
     * \param binddn the LDAP Bind DN to set
     */
    void setBindDn(const QString &binddn);

    /*!
     * Returns the bind DN. KConfig widget name: kcfg_ldapbinddn
     */
    [[nodiscard]] QString bindDn() const;

    /*!
     * Sets the SASL realm. KConfig widget name: kcfg_ldaprealm
     * \param realm the SASL realm to set
     */
    void setRealm(const QString &realm);

    /*!
     * Returns the SASL realm. KConfig widget name: kcfg_ldaprealm
     */
    [[nodiscard]] QString realm() const;

    /*!
     * Sets the host name. KConfig widget name: kcfg_ldaphost
     * \param host the LDAP host to set
     */
    void setHost(const QString &host);

    /*!
     * Returns the host name. KConfig widget name: kcfg_ldaphost
     */
    [[nodiscard]] QString host() const;

    /*!
     * Sets the LDAP port. KConfig widget name: kcfg_ldapport
     * \param port the LDAP port to set
     */
    void setPort(int port);

    /*!
     * Returns the LDAP port. KConfig widget name: kcfg_ldapport
     */
    [[nodiscard]] int port() const;

    /*!
     * Sets the LDAP protocol version. KConfig widget name: kcfg_ldapver
     * \param version the LDAP protocol version to set
     */
    void setVersion(int version);

    /*!
     * Returns the LDAP protocol version. KConfig widget name: kcfg_ldapver
     */
    [[nodiscard]] int version() const;

    /*!
     * Sets the LDAP Base DN. KConfig widget name: kcfg_ldapdn
     * \param dn the LDAP Base DN to set
     */
    void setDn(const KLDAPCore::LdapDN &dn);

    /*!
     * Returns the LDAP Base DN. KConfig widget name: kcfg_ldapdn
     */
    [[nodiscard]] KLDAPCore::LdapDN dn() const;

    /*!
     * Sets the LDAP Filter. KConfig widget name: kcfg_ldapfilter
     * \param filter the LDAP Filter to set
     */
    void setFilter(const QString &filter);

    /*!
     * Returns the LDAP Filter. KConfig widget name: kcfg_ldapfilter
     */
    [[nodiscard]] QString filter() const;

    /*!
     * Sets the SASL Mechanism. KConfig widget name: kcfg_ldapsaslmech
     * \param mech the SASL Mechanism to set
     */
    void setMech(const QString &mech);

    /*!
     * Returns the SASL Mechanism. KConfig widget name: kcfg_ldapsaslmech
     */
    [[nodiscard]] QString mech() const;

    /*!
     * Sets the security type (None, SSL, TLS).
     * KConfig widget names: kcfg_ldapnosec, kcfg_ldaptls, kcfg_ldapssl
     * \param security the security type to set
     */
    void setSecurity(Security security);

    /*!
     * Returns the security type.
     * KConfig widget names: kcfg_ldapnosec, kcfg_ldaptls, kcfg_ldapssl
     */
    [[nodiscard]] Security security() const;

    /*!
     * Sets the authentication type (Anonymous, Simple, SASL).
     * KConfig widget names: kcfg_ldapanon, kcfg_ldapsimple, kcfg_ldapsasl
     * \param auth the authentication type to set
     */
    void setAuth(Auth auth);

    /*!
     * Returns the authentication type.
     * KConfig widget names: kcfg_ldapanon, kcfg_ldapsimple, kcfg_ldapsasl
     */
    [[nodiscard]] Auth auth() const;

    /*!
     * Sets the size limit.
     * KConfig widget name: kcfg_ldapsizelimit
     * \param sizelimit the size limit to set
     */
    void setSizeLimit(int sizelimit);

    /*!
     * Returns the size limit.
     * KConfig widget name: kcfg_ldapsizelimit
     */
    [[nodiscard]] int sizeLimit() const;

    /*!
     * Sets the time limit.
     * KConfig widget name: kcfg_ldaptimelimit
     * \param timelimit the time limit to set
     */
    void setTimeLimit(int timelimit);

    /*!
     * Returns the time limit.
     * KConfig widget name: kcfg_ldaptimelimit
     */
    [[nodiscard]] int timeLimit() const;

    /*!
     * Sets the page size.
     * KConfig widget name: kcfg_ldappagesize
     * \param pagesize the page size to set
     */
    void setPageSize(int pagesize);

    /*!
     * Returns the page size.
     * KConfig widget name: kcfg_ldappagesize
     */
    [[nodiscard]] int pageSize() const;

    /*!
     * Returns the features flags.
     */
    [[nodiscard]] WinFlags features() const;

    /*!
     * Sets the features flags.
     * \param features the features to set
     */
    void setFeatures(WinFlags features);

    /*!
     * Returns an LDAP URL constructed from the settings given.
     * Extensions are filled for use in the LDAP KIO worker.
     */
    [[nodiscard]] KLDAPCore::LdapUrl url() const;

    /*!
     * Sets up the widget via an LDAP URL.
     * \param url the LDAP URL to set
     */
    void setUrl(const KLDAPCore::LdapUrl &url);

    /*!
     * Returns an LdapServer object constructed from the settings given.
     */
    [[nodiscard]] KLDAPCore::LdapServer server() const;

    /*!
     * Sets up the widget via an LdapServer object.
     * \param server the LdapServer object to set
     */
    void setServer(const KLDAPCore::LdapServer &server);

Q_SIGNALS:
    /*!
     * Emitted when the host name has changed.
     * \since 4.13
     * \param hostName the new host name
     */
    void hostNameChanged(const QString &);

private:
    class LdapConfigWidgetPrivate;
    std::unique_ptr<LdapConfigWidgetPrivate> const d;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(KLDAPWidgets::LdapConfigWidget::WinFlags)
}
