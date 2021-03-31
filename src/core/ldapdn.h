/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2006 Sean Harmer <sh@theharmers.co.uk>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kldap_export.h"
#include <QString>

namespace KLDAP
{
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

    Q_REQUIRED_RESULT bool operator==(const LdapDN &rhs) const;

    Q_REQUIRED_RESULT bool operator!=(const LdapDN &rhs) const;

private:
    class LdapDNPrivate;
    LdapDNPrivate *const d;
};
}

