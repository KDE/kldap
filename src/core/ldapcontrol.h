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

#ifndef KLDAP_LDAPCONTROL_H
#define KLDAP_LDAPCONTROL_H

#include <QString>
#include <QVector>
#include <QSharedDataPointer>
class LdapControlPrivate;

#include "kldap_export.h"

// clazy:excludeall=copyable-polymorphic

namespace KLDAP {
class LdapControl;
typedef QVector<LdapControl> LdapControls;

/**
  @brief
  This class represents an LDAP Control
*/
class KLDAP_EXPORT LdapControl
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
    Q_REQUIRED_RESULT QString oid() const;
    /**
     * Returns the control's value.
     */
    Q_REQUIRED_RESULT QByteArray value() const;
    /**
     * Returns the control's criticality.
     */
    Q_REQUIRED_RESULT bool critical() const;

    /**
     * Parses a paging results control, which the server returned.
     * Puts the server's cookie into @p cookie, and returns the estimated
     * result set size. If the OID is not the page control's OID, or the
     * value cannot be decoded, returns -1.
     * @param cookie the cookie to hold server's cookie
     */
    Q_REQUIRED_RESULT int parsePageControl(QByteArray &cookie) const;
    /**
     * Creates a paging search control.
     */
    Q_REQUIRED_RESULT static LdapControl createPageControl(int pagesize, const QByteArray &cookie = QByteArray());

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

#endif
