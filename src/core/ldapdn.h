/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2006 Sean Harmer <sh@theharmers.co.uk>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kldap_core_export.h"
#include <QString>
#include <memory>
namespace KLDAPCore
{
class KLDAP_CORE_EXPORT LdapDN
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
    [[nodiscard]] QString toString() const;

    /**
     * \param depth The depth of the DN to return using a zero-based index.
     * \returns A QString representing the DN levels deep in the directory.
     */
    [[nodiscard]] QString toString(int depth) const;

    /**
     * \returns A QString representing the RDN of this DN.
     */
    [[nodiscard]] QString rdnString() const;

    /**
     * \param depth The depth of the RDN to return using a zero-based index.
     * \returns A QString representing the RDN levels deep in the directory.
     */
    [[nodiscard]] QString rdnString(int depth) const;

    /**
     * \returns True if this is a valid DN, false otherwise.
     */
    [[nodiscard]] bool isValid() const;

    /**
     * \returns The depth of this DN in the directory.
     */
    [[nodiscard]] int depth() const;

    [[nodiscard]] bool operator==(const LdapDN &rhs) const;

    [[nodiscard]] bool operator!=(const LdapDN &rhs) const;

private:
    class LdapDNPrivate;
    std::unique_ptr<LdapDNPrivate> const d;
};
}
