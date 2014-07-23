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

#include "ldapobject.h"
#include "ldif.h"

#include <QtCore/QSharedData>

using namespace KLDAP;

class LdapObject::Private : public QSharedData
{
public:
    Private()
    {
    }

    Private(const Private &other)
        : QSharedData(other)
    {
        mDn = other.mDn;
        mAttrs = other.mAttrs;
    }

    LdapDN mDn;
    LdapAttrMap mAttrs;
};

LdapObject::LdapObject()
    : d(new Private)
{
}

LdapObject::LdapObject(const QString &dn)
    : d(new Private)
{
    d->mDn = LdapDN(dn);
}

LdapObject::~LdapObject()
{
}

LdapObject::LdapObject(const LdapObject &that)
    : d(that.d)
{
}

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
    QString result = QString::fromLatin1("dn: %1\n").arg(d->mDn.toString());
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
    d->mAttrs[ attributeName ] = values;
}

void LdapObject::addValue(const QString &attributeName, const QByteArray &value)
{
    d->mAttrs[ attributeName ].append(value);
}

LdapAttrValue LdapObject::values(const QString &attributeName) const
{
    if (hasAttribute(attributeName)) {
        return d->mAttrs.value(attributeName);
    } else {
        return LdapAttrValue();
    }
}

QByteArray LdapObject::value(const QString &attributeName) const
{
    if (hasAttribute(attributeName)) {
        return d->mAttrs.value(attributeName).first();
    } else {
        return QByteArray();
    }
}

bool LdapObject::hasAttribute(const QString &attributeName) const
{
    return d->mAttrs.contains(attributeName);
}
