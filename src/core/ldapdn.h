/*
  This file is part of libkldap.
  Copyright (c) 2006 Sean Harmer <sh@theharmers.co.uk>

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

#ifndef KLDAP_LDAPDN_H
#define KLDAP_LDAPDN_H

#include "kldap_export.h"
#include <QString>

namespace KLDAP {
class KLDAP_EXPORT LdapDN
{
public:
    explicit LdapDN();
    explicit LdapDN(const QString &dn);

    LdapDN(const LdapDN &that);
    LdapDN &operator=(const LdapDN &that);

    ~LdapDN();

    void clear();

    bool isEmpty() const;

    /**
     * \returns A QString representing the DN.
     */
    Q_REQUIRED_RESULT QString toString() const;

    /**
     * \param depth The depth of the DN to return using a zero-based index.
     * \returns A QString representing the DN levels deep in the directory.
     */
    Q_REQUIRED_RESULT QString toString(int depth) const;

    /**
     * \returns A QString representing the RDN of this DN.
     */
    Q_REQUIRED_RESULT QString rdnString() const;

    /**
     * \param depth The depth of the RDN to return using a zero-based index.
     * \returns A QString representing the RDN levels deep in the directory.
     */
    Q_REQUIRED_RESULT QString rdnString(int depth) const;

    /**
     * \returns True if this is a valid DN, false otherwise.
     */
    Q_REQUIRED_RESULT bool isValid() const;

    /**
     * \returns The depth of this DN in the directory.
     */
    Q_REQUIRED_RESULT int depth() const;

    Q_REQUIRED_RESULT bool operator ==(const LdapDN &rhs) const;

    Q_REQUIRED_RESULT bool operator !=(const LdapDN &rhs) const;

private:
    class LdapDNPrivate;
    LdapDNPrivate *const d;
};
}

#endif
