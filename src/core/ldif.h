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

#ifndef KLDAP_LDIF_H
#define KLDAP_LDIF_H

#include <QString>
#include <QByteArray>

#include "ldapdn.h"
#include "kldap_export.h"

// clazy:excludeall=copyable-polymorphic

namespace KLDAP {
/**
 * Ldif
 *
 * Ldif implements an RFC 2849 compliant Ldif parser. Ldif files are used to
 * represent directory information on LDAP-based servers, or to describe a set
 * of changes which are to be applied to a directory.
 */

class KLDAP_EXPORT Ldif
{
public:

    typedef enum {
        None, NewEntry, EndEntry, Item, Control, Err, MoreData
    } ParseValue;

    typedef enum {
        Entry_None, Entry_Add, Entry_Del, Entry_Mod, Entry_Modrdn
    } EntryType;

    typedef enum {
        Mod_None, Mod_Add, Mod_Replace, Mod_Del
    } ModType;

    Ldif();

    Ldif(const Ldif &that);
    Ldif &operator=(const Ldif &that);

    ~Ldif();

    /**
     * Assembles fieldname and value into a valid Ldif line, BASE64 encodes the
     * value if necessary and optionally splits into more lines.
     * @param fieldname The name of the entry.
     * @param value The value of the entry.
     * @param linelen Maximum length of the lines in the result.
     * @param url If true, encode value as url ( use :< ).
     */
    Q_REQUIRED_RESULT static QByteArray assembleLine(const QString &fieldname, const QByteArray &value, uint linelen = 0, bool url = false);
    /**
     * This is the same as the above function, the only difference that
     * this accepts QString as the value.
     */
    Q_REQUIRED_RESULT static QByteArray assembleLine(const QString &fieldname, const QString &value, uint linelen = 0, bool url = false);

    /**
     * Splits one line from an Ldif file to attribute and value components.
     * @return true if value is an URL, false otherwise
     */
    Q_REQUIRED_RESULT static bool splitLine(const QByteArray &line, QString &fieldname, QByteArray &value);

    /**
     * Splits a control specification (without the "control:" directive)
     * @param line is the control directive
     * @param oid will contain the OID
     * @param critical will contain the criticality of control
     * @param value is the control value
     */
    Q_REQUIRED_RESULT static bool splitControl(const QByteArray &line, QString &oid, bool &critical, QByteArray &value);

    /**
     * Starts the parsing of a new Ldif
     */
    void startParsing();

    /**
     * Process one Ldif line
     */
    Q_REQUIRED_RESULT ParseValue processLine();

    /**
     * Process the Ldif until a complete item can be returned
     * @return NewEntry if a new DN encountered, Item if a new item returned,
     * Err if the Ldif contains error, EndEntry if the parser reached the end
     * of the current entry and MoreData if the parser encountered the end of
     * the current chunk of the Ldif.
     *
     * If you want to finish the parsing after receiving MoreData, then call
     * endLdif(), so the parser can safely flush the current entry.
     */
    Q_REQUIRED_RESULT ParseValue nextItem();

    /**
     * Sets a chunk of Ldif. Call before startParsing(), or if nextItem()
     * returned MoreData.
     * @param ldif the Ldif chunk to set
     */
    void setLdif(const QByteArray &ldif);

    /**
     * Indicates the end of the Ldif file/stream. Call if nextItem() returned
     * MoreData, but actually you don't have more data.
     */
    void endLdif();

    /**
     * Returns the requested LDAP operation extracted from the current entry.
     */
    Q_REQUIRED_RESULT EntryType entryType() const;

    /**
     * Returns the LDAP modify request type if entryType() returned Entry_Mod.
     */
    Q_REQUIRED_RESULT int modType() const;

    /**
     * Returns the Distinguished Name of the current entry.
     */
    Q_REQUIRED_RESULT LdapDN dn() const;

    /**
     * Returns the new Relative Distinguished Name if modType() returned
     * Entry_Modrdn.
     */
    Q_REQUIRED_RESULT QString newRdn() const;

    /**
     * Returns the new parent of the entry if modType() returned Entry_Modrdn.
     */
    QString newSuperior() const;

    /**
     * Returns if the delete of the old RDN is required.
     */
    Q_REQUIRED_RESULT bool delOldRdn() const;

    /**
     * Returns the attribute name.
     */
    Q_REQUIRED_RESULT QString attr() const;

    /**
     * Returns the attribute value.
     */
    Q_REQUIRED_RESULT QByteArray value() const;

    /**
     * Returns if val() is an url
     */
    Q_REQUIRED_RESULT bool isUrl() const;

    /**
     * Returns the criticality level when modType() returned Control.
     */
    Q_REQUIRED_RESULT bool isCritical() const;

    /**
     * Returns the OID when modType() returned Control.
     */
    Q_REQUIRED_RESULT QString oid() const;

    /**
     * Returns the line number which the parser processes.
     */
    Q_REQUIRED_RESULT uint lineNumber() const;

private:
    class LdifPrivate;
    LdifPrivate *const d;
};
}

#endif
