/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QList>
#include <QSharedDataPointer>
#include <QString>
class LdapControlPrivate;

#include "kldap_core_export.h"

// clazy:excludeall=copyable-polymorphic

namespace KLDAPCore
{
class LdapControl;
using LdapControls = QList<LdapControl>;

/**
  @brief
  This class represents an LDAP Control
*/
class KLDAP_CORE_EXPORT LdapControl
{
public:
    /**
     * Creates an empty control.
     */
    LdapControl();
    /**
     * Creates a control with the given OID, value and criticality.
     */
    LdapControl(const QString &oid, const QByteArray &value, bool critical = false);

    LdapControl(const LdapControl &that);
    LdapControl &operator=(const LdapControl &that);
    /**
     * Destroys the control object.
     */
    ~LdapControl();
    /**
     * Sets the control's OID, value and criticality.
     */
    void setControl(const QString &oid, const QByteArray &value, bool critical = false);
    /**
     * Sets the control's OID.
     */
    void setOid(const QString &oid);
    /**
     * Sets the control's value.
     */
    void setValue(const QByteArray &value);
    /**
     * Sets the control's criticality.
     */
    void setCritical(bool critical);
    /**
     * Returns the control's OID.
     */
    [[nodiscard]] QString oid() const;
    /**
     * Returns the control's value.
     */
    [[nodiscard]] QByteArray value() const;
    /**
     * Returns the control's criticality.
     */
    [[nodiscard]] bool critical() const;

    /**
     * Parses a paging results control, which the server returned.
     * Puts the server's cookie into @p cookie, and returns the estimated
     * result set size. If the OID is not the page control's OID, or the
     * value cannot be decoded, returns -1.
     * @param cookie the cookie to hold server's cookie
     */
    [[nodiscard]] int parsePageControl(QByteArray &cookie) const;
    /**
     * Creates a paging search control.
     */
    [[nodiscard]] static LdapControl createPageControl(int pagesize, const QByteArray &cookie = QByteArray());

    /**
     * Inserts a unique control against a list of controls.
     * If the control already exists in the list is is updated, otherwise
     * it is appended to the list.
     * @param list the current list of controls
     * @param ctrl the control to insert
     * @since 4.4
     */
    static void insert(LdapControls &list, const LdapControl &ctrl);

private:
    QSharedDataPointer<LdapControlPrivate> d;
};
}
