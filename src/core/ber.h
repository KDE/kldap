/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QByteArray>

#include "kldap_core_export.h"
#include <memory>
// clazy:excludeall=copyable-polymorphic

namespace KLDAPCore
{
/**
 * This class allows encoding and decoding Qt structures using Basic
 * Encoding Rules.
 */
class KLDAP_CORE_EXPORT Ber
{
public:
    /**
     * Constructs a Ber object.
     */
    Ber();
    /**
     * Constructs a Ber object from the value.
     */
    explicit Ber(const QByteArray &value);
    /**
     * Destroys the Ber object.
     */
    ~Ber();

    Ber(const Ber &that);
    Ber &operator=(const Ber &that);

    /**
     * Returns the Ber object as a flat QByteArray.
     */
    [[nodiscard]] QByteArray flatten() const;

    /**
     * Appends the data with the specified format to the Ber object.
     * This function works like printf, except that it's appending the
     * parameters, not replacing them. The allowed format characters and
     * the expected parameter types are:
     * <ul>
     *   <li>
     *     b  Boolean.  An int parameter should be supplied.
     *     A boolean element is output.
     *   </li>
     *   <li>
     *     e  Enumeration.  An int parameter should be supplied.
     *     An  enumeration  element is output.
     *   </li>
     *   <li>
     *     i  Integer.   An int parameter should be supplied.
     *     An integer element is output.
     *   </li>
     *   <li>
     *     B  Bitstring.  A pointer to a QByteArray which contains the
     *     bitstring is supplied, followed by the number of bits in the
     *     bitstring.  A bitstring element is output.
     *   </li>
     *   <li>
     *     n  Null.  No parameter is required. A null element is output.
     *   </li>
     *   <li>
     *     O,o,s  Octet  string.  A QByteArray * is supplied.
     *     An octet string element is output.
     *         Due to versatility of Qt's QByteArray, these three format
     *         strings are all accepts the same parameter, but using the 's'
     *         format the string will be encoded only to the first zero
     *         character (a null terminated string)!
     *   </li>
     *   <li>
     *     t  Tag.  An int specifying the tag to give the next element
     *     is provided. This works across calls.
     *   </li>
     *   <li>
     *     v,V  Several octet strings. A QList<QByteArray>* is supplied.
     *     Note that a construct like ’{v}’ is required to get an actual
     *     SEQUENCE OF octet strings. Also note that the 'v' format recognizes
     *     the QByteArray only to the first zero character, so it's not
     *     appropriate for binary data, just only for null terminated strings!
     *   </li>
     *   <li>
     *     {  Begin sequence. No parameter is required.
     *   </li>
     *   <li>
     *     }  End sequence.  No parameter is required.
     *   </li>
     *   <li>
     *     [  Begin set.  No parameter is required.
     *   </li>
     *   <li>
     *     ]  End set.  No parameter is required.
     *   </li>
     * </ul>
     */
    int printf(QString format, ...); // Passing by-value since it's used by va_start
    int scanf(QString format, ...);
    unsigned int peekTag(int &size);
    unsigned int skipTag(int &size);

private:
    class BerPrivate;
    std::unique_ptr<BerPrivate> const d;
};
}
