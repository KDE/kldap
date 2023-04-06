/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapcontrol.h"
#include "ber.h"

#include <QSharedData>

using namespace KLDAPCore;

class LdapControlPrivate : public QSharedData
{
public:
    LdapControlPrivate() = default;

    LdapControlPrivate(const LdapControlPrivate &other) = default;

    QString mOid;
    QByteArray mValue;
    bool mCritical = false;
};

LdapControl::LdapControl()
    : d(new LdapControlPrivate)
{
    setControl(QString(), QByteArray(), false);
}

LdapControl::LdapControl(const QString &oid, const QByteArray &value, bool critical)
    : d(new LdapControlPrivate)
{
    setControl(oid, value, critical);
}

LdapControl::LdapControl(const LdapControl &that)
    : d(that.d)
{
    setControl(that.d->mOid, that.d->mValue, that.d->mCritical);
}

LdapControl &LdapControl::operator=(const LdapControl &that)
{
    if (this != &that) {
        d = that.d;
    }

    setControl(that.d->mOid, that.d->mValue, that.d->mCritical);

    return *this;
}

LdapControl::~LdapControl() = default;

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
    if (ber.scanf(QStringLiteral("{iO}"), &size, &cookie) == -1) {
        return -1;
    } else {
        return size;
    }
}

LdapControl LdapControl::createPageControl(int pagesize, const QByteArray &cookie)
{
    LdapControl control;
    Ber ber;

    ber.printf(QStringLiteral("{iO}"), pagesize, &cookie);
    control.setOid(QStringLiteral("1.2.840.113556.1.4.319"));
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
