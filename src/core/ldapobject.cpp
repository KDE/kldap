/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapobject.h"
#include "ldif.h"

#include <QSharedData>

using namespace KLDAPCore;

class LdapObjectPrivate : public QSharedData
{
public:
    LdapObjectPrivate() = default;

    LdapObjectPrivate(const LdapObjectPrivate &other)
        : QSharedData(other)
        , mDn(other.mDn)
        , mAttrs(other.mAttrs)
    {
    }

    LdapDN mDn;
    LdapAttrMap mAttrs;
};

LdapObject::LdapObject()
    : d(new LdapObjectPrivate)
{
}

LdapObject::LdapObject(const QString &dn)
    : d(new LdapObjectPrivate)
{
    d->mDn = LdapDN(dn);
}

LdapObject::~LdapObject() = default;

LdapObject::LdapObject(const LdapObject &that)

    = default;

LdapObject &LdapObject::operator=(const LdapObject &that)
{
    if (this != &that) {
        d = that.d;
    }

    return *this;
}

void LdapObject::setDn(const LdapDN &dn)
{
    d->mDn = dn;
}

void LdapObject::setDn(const QString &dn)
{
    d->mDn = LdapDN(dn);
}

void LdapObject::setAttributes(const LdapAttrMap &attrs)
{
    d->mAttrs = attrs;
}

LdapDN LdapObject::dn() const
{
    return d->mDn;
}

const LdapAttrMap &LdapObject::attributes() const
{
    return d->mAttrs;
}

QString LdapObject::toString() const
{
    QString result = QStringLiteral("dn: %1\n").arg(d->mDn.toString());
    LdapAttrMap::ConstIterator end(d->mAttrs.constEnd());
    for (LdapAttrMap::ConstIterator it = d->mAttrs.constBegin(); it != end; ++it) {
        const QString attr = it.key();
        LdapAttrValue::ConstIterator end2((*it).constEnd());
        for (LdapAttrValue::ConstIterator it2 = (*it).constBegin(); it2 != end2; ++it2) {
            result += QString::fromUtf8(Ldif::assembleLine(attr, *it2, 76)) + QLatin1Char('\n');
        }
    }
    return result;
}

void LdapObject::clear()
{
    d->mDn.clear();
    d->mAttrs.clear();
}

void LdapObject::setValues(const QString &attributeName, const LdapAttrValue &values)
{
    d->mAttrs[attributeName] = values;
}

void LdapObject::addValue(const QString &attributeName, const QByteArray &value)
{
    d->mAttrs[attributeName].append(value);
}

LdapAttrValue LdapObject::values(const QString &attributeName) const
{
    if (hasAttribute(attributeName)) {
        return d->mAttrs.value(attributeName);
    } else {
        return {};
    }
}

QByteArray LdapObject::value(const QString &attributeName) const
{
    if (hasAttribute(attributeName)) {
        return d->mAttrs.value(attributeName).first();
    } else {
        return {};
    }
}

bool LdapObject::hasAttribute(const QString &attributeName) const
{
    return d->mAttrs.contains(attributeName);
}
