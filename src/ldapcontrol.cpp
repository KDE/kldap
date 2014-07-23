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

#include "ldapcontrol.h"
#include "ber.h"

#include <QtCore/QSharedData>

using namespace KLDAP;

class LdapControl::Private : public QSharedData
{
public:
    Private()
    {
        mCritical = false;
    }

    Private(const Private &other)
        : QSharedData(other)
    {
        mOid = other.mOid;
        mValue = other.mValue;
        mCritical = other.mCritical;
    }

    QString mOid;
    QByteArray mValue;
    bool mCritical;
};

LdapControl::LdapControl()
    : d(new Private)
{
    setControl(QString(), QByteArray(), false);
}

LdapControl::LdapControl(const QString &oid, const QByteArray &value, bool critical)
    : d(new Private)
{
    setControl(oid, value, critical);
}

LdapControl::LdapControl(const LdapControl &that)
    : d(that.d)
{
    setControl(that.d->mOid, that.d->mValue, that.d->mCritical);
}

LdapControl &LdapControl::operator= (const LdapControl &that)
{
    if (this != &that) {
        d = that.d;
    }

    setControl(that.d->mOid, that.d->mValue, that.d->mCritical);

    return *this;
}

LdapControl::~LdapControl()
{
}

void LdapControl::setControl(const QString &oid, const QByteArray &value, bool critical)
{
    d->mOid = oid;
    d->mValue = value;
    d->mCritical = critical;
}

QString LdapControl::oid() const
{
    return d->mOid;
}

QByteArray LdapControl::value() const
{
    return d->mValue;
}

bool LdapControl::critical() const
{
    return d->mCritical;
}

void LdapControl::setOid(const QString &oid)
{
    d->mOid = oid;
}

void LdapControl::setValue(const QByteArray &value)
{
    d->mValue = value;
}

void LdapControl::setCritical(bool critical)
{
    d->mCritical = critical;
}

int LdapControl::parsePageControl(QByteArray &cookie) const
{
    if (d->mOid != QLatin1String("1.2.840.113556.1.4.319")) {
        return -1;
    }

    Ber ber(d->mValue);
    int size;
    if (ber.scanf(QLatin1String("{iO}"), &size, &cookie) == -1) {
        return -1;
    } else {
        return size;
    }
}

LdapControl LdapControl::createPageControl(int pagesize, const QByteArray &cookie)
{
    LdapControl control;
    Ber ber;

    ber.printf(QLatin1String("{iO}"), pagesize, &cookie);
    control.setOid(QLatin1String("1.2.840.113556.1.4.319"));
    control.setValue(ber.flatten());
    return control;
}

void LdapControl::insert(LdapControls &list, const LdapControl &ctrl)
{
    LdapControls::iterator it;
    LdapControls::iterator endit = list.end();
    const QString oid = ctrl.oid();

    for (it = list.begin(); it != endit; ++it) {
        if (it->oid() == oid) {
            *it = ctrl;
            return;
        }
    }
    list.append(ctrl);
}
