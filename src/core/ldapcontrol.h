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

/*!
  \class KLDAPCore::LdapControl
  \inmodule LdapCore
  \inheaderfile KLDAPCore/LdapControl

  \brief
  This class represents an LDAP Control
*/
class KLDAP_CORE_EXPORT LdapControl
{
public:
    /*!
     * Creates an empty control.
     */
    LdapControl();

    /*!
     * Creates a control with the given OID, value and criticality.
     * \param oid the OID of the control
     * \param value the value of the control
     * \param critical whether the control is critical
     */
    LdapControl(const QString &oid, const QByteArray &value, bool critical = false);

    /*!
     * Constructs a copy of the given control.
     * \param that the control to copy
     */
    LdapControl(const LdapControl &that);

    /*!
     * Assigns the given control to this control.
     * \param that the control to assign
     * \return a reference to this control
     */
    LdapControl &operator=(const LdapControl &that);

    /*!
     * Destroys the control object.
     */
    ~LdapControl();

    /*!
     * Sets the control's OID, value and criticality.
     * \param oid the OID to set
     * \param value the value to set
     * \param critical whether the control is critical
     */
    void setControl(const QString &oid, const QByteArray &value, bool critical = false);

    /*!
     * Sets the control's OID.
     * \param oid the OID to set
     */
    void setOid(const QString &oid);

    /*!
     * Sets the control's value.
     * \param value the value to set
     */
    void setValue(const QByteArray &value);

    /*!
     * Sets the control's criticality.
     * \param critical whether the control is critical
     */
    void setCritical(bool critical);

    /*!
     * Returns the control's OID.
     * \return the OID string
     */
    [[nodiscard]] QString oid() const;

    /*!
     * Returns the control's value.
     * \return the value byte array
     */
    [[nodiscard]] QByteArray value() const;

    /*!
     * Returns the control's criticality.
     * \return true if the control is critical
     */
    [[nodiscard]] bool critical() const;

    /*!
     * Parses a paging results control returned by the server.
     * Puts the server's cookie into the output parameter and returns the estimated
     * result set size. If the OID is not the page control's OID, or the
     * value cannot be decoded, returns -1.
     * \param cookie output parameter to hold server's cookie
     * \return the estimated result set size, or -1 if parsing failed
     */
    [[nodiscard]] int parsePageControl(QByteArray &cookie) const;

    /*!
     * Creates a paging search control.
     * \param pagesize the page size
     * \param cookie the cookie from a previous search (for continuation)
     * \return the created paging control
     */
    [[nodiscard]] static LdapControl createPageControl(int pagesize, const QByteArray &cookie = QByteArray());

    /*!
     * Inserts a unique control into a list of controls.
     * If the control already exists in the list it is updated, otherwise
     * it is appended to the list.
     * \param list the current list of controls
     * \param ctrl the control to insert
     * \since 4.4
     */
    static void insert(LdapControls &list, const LdapControl &ctrl);

private:
    QSharedDataPointer<LdapControlPrivate> d;
};
}
