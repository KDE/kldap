/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2006 Sean Harmer <sh@theharmers.co.uk>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapdn.h"

#include "ldap_core_debug.h"
#include <algorithm>

using namespace KLDAPCore;

class Q_DECL_HIDDEN LdapDN::LdapDNPrivate
{
public:
    LdapDNPrivate() = default;

    ~LdapDNPrivate() = default;

    [[nodiscard]] bool isValidRDNString(const QString &rdn) const;
    [[nodiscard]] QStringList splitOnNonEscapedChar(const QString &rdn, QChar ch) const;

    QString m_dn;
};

bool LdapDN::LdapDNPrivate::isValidRDNString(const QString &rdn) const
{
    qCDebug(LDAP_LOG) << "Testing rdn:" << rdn;

    // If it is a muli-valued rdn, split it into its constituent parts
    const QStringList rdnParts = splitOnNonEscapedChar(rdn, QLatin1Char('+'));
    const int rdnPartsSize(rdnParts.size());
    if (rdnPartsSize > 1) {
        for (int i = 0; i < rdnPartsSize; i++) {
            if (!isValidRDNString(rdnParts.at(i))) {
                return false;
            }
        }
        return true;
    }
    // Split the rdn into the attribute name and value parts
    const auto components = QStringView(rdn).split(QLatin1Char('='));
    // We should have exactly two parts
    if (components.size() != 2) {
        return false;
    }

    return true;
}

QStringList LdapDN::LdapDNPrivate::splitOnNonEscapedChar(const QString &str, QChar ch) const
{
    QStringList strParts;
    int index = 0;
    int searchFrom = 0;
    int strPartStartIndex = 0;
    while ((index = str.indexOf(ch, searchFrom)) != -1) {
        const QChar prev = str[std::max(0, index - 1)];
        if (prev != QLatin1Char('\\')) {
            // Found a component of a multi-valued RDN
            // qCDebug(LDAP_LOG) << "Found" << ch << "at index" << index;
            QString tmp = str.mid(strPartStartIndex, index - strPartStartIndex);
            // qCDebug(LDAP_LOG) << "Adding part:" << tmp;
            strParts.append(tmp);
            strPartStartIndex = index + 1;
        }

        searchFrom = index + 1;
    }

    // Add on the part after the last found delimiter
    QString tmp = str.mid(strPartStartIndex);
    // qCDebug(LDAP_LOG) << "Adding part:" << tmp;
    strParts.append(tmp);

    return strParts;
}

LdapDN::LdapDN()
    : d(new LdapDNPrivate)
{
}

LdapDN::LdapDN(const QString &dn)
    : d(new LdapDNPrivate)
{
    d->m_dn = dn;
}

LdapDN::LdapDN(const LdapDN &that)
    : d(new LdapDNPrivate)
{
    *d = *that.d;
}

LdapDN &LdapDN::operator=(const LdapDN &that)
{
    if (this == &that) {
        return *this;
    }

    *d = *that.d;
    return *this;
}

LdapDN::~LdapDN() = default;

void LdapDN::clear()
{
    d->m_dn.clear();
}

bool LdapDN::isEmpty() const
{
    return d->m_dn.isEmpty();
}

QString LdapDN::toString() const
{
    return d->m_dn;
}

QString LdapDN::toString(int depth) const
{
    const QStringList rdns = d->splitOnNonEscapedChar(d->m_dn, QLatin1Char(','));
    if (depth >= rdns.size()) {
        return {};
    }

    // Construct a DN down to the requested depth
    QString dn;
    for (int i = depth; i >= 0; i--) {
        dn += rdns.at(rdns.size() - 1 - i) + QLatin1Char(',');
        qCDebug(LDAP_LOG) << "dn =" << dn;
    }
    dn.chop(1); // Strip off the extraneous comma

    return dn;
}

QString LdapDN::rdnString() const
{
    /** \TODO We should move this into the d pointer as we calculate rdns quite a lot */
    const QStringList rdns = d->splitOnNonEscapedChar(d->m_dn, QLatin1Char(','));
    return rdns.at(0);
}

QString LdapDN::rdnString(int depth) const
{
    const QStringList rdns = d->splitOnNonEscapedChar(d->m_dn, QLatin1Char(','));
    if (depth >= rdns.size()) {
        return {};
    }
    return rdns.at(rdns.size() - 1 - depth);
}

bool LdapDN::isValid() const
{
    qCDebug(LDAP_LOG) << "Testing dn:" << d->m_dn;

    // Break the string into rdn's
    const QStringList rdns = d->splitOnNonEscapedChar(d->m_dn, QLatin1Char(','));

    // Test to see if each rdn is valid
    const int rdnsSize(rdns.size());
    for (int i = 0; i < rdnsSize; i++) {
        if (!d->isValidRDNString(rdns.at(i))) {
            return false;
        }
    }

    return true;
}

int LdapDN::depth() const
{
    const QStringList rdns = d->splitOnNonEscapedChar(d->m_dn, QLatin1Char(','));
    return rdns.size();
}

bool LdapDN::operator==(const LdapDN &rhs) const
{
    return d->m_dn == rhs.d->m_dn;
}

bool LdapDN::operator!=(const LdapDN &rhs) const
{
    return d->m_dn != rhs.d->m_dn;
}
