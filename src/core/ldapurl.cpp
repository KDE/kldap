/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapurl.h"

#include "ldap_core_debug.h"

using namespace KLDAPCore;
using namespace Qt::Literals::StringLiterals;

class Q_DECL_HIDDEN LdapUrl::LdapUrlPrivate
{
public:
    LdapUrlPrivate()
    {
    }

    QMap<QString, Extension> m_extensions;
    QStringList m_attributes;
    Scope m_scope{Base};
    QString m_filter;
};

LdapUrl::LdapUrl()
    : d(new LdapUrlPrivate)
{
}

LdapUrl::LdapUrl(const QUrl &_url)
    : QUrl(_url)
    , d(new LdapUrlPrivate)
{
    parseQuery();
}

LdapUrl::LdapUrl(const LdapUrl &that)
    : QUrl(that)
    , d(new LdapUrlPrivate)
{
    *d = *that.d;
}

LdapUrl &LdapUrl::operator=(const LdapUrl &that)
{
    if (this == &that) {
        return *this;
    }

    QUrl::operator=(that);
    *d = *that.d;

    return *this;
}

LdapUrl::~LdapUrl() = default;

void LdapUrl::setDn(const LdapDN &dn)
{
    const QString tmp = dn.toString();
    if (tmp.startsWith(u'/')) {
        setPath(tmp);
    } else {
        setPath(u'/' + tmp);
    }
}

LdapDN LdapUrl::dn() const
{
    QString tmp = path();
    if (tmp.startsWith(u'/')) {
        tmp = tmp.mid(1);
    }
    const LdapDN tmpDN(tmp);
    return tmpDN;
}

QStringList LdapUrl::attributes() const
{
    return d->m_attributes;
}

void LdapUrl::setAttributes(const QStringList &attributes)
{
    d->m_attributes = attributes;
    updateQuery();
}

LdapUrl::Scope LdapUrl::scope() const
{
    return d->m_scope;
}

void LdapUrl::setScope(Scope scope)
{
    d->m_scope = scope;
    updateQuery();
}

QString LdapUrl::filter() const
{
    return d->m_filter;
}

void LdapUrl::setFilter(const QString &filter)
{
    d->m_filter = filter;
    updateQuery();
}

bool LdapUrl::hasExtension(const QString &key) const
{
    return d->m_extensions.contains(key);
}

LdapUrl::Extension LdapUrl::extension(const QString &key) const
{
    QMap<QString, Extension>::const_iterator it;

    it = d->m_extensions.constFind(key);
    if (it != d->m_extensions.constEnd()) {
        return *it;
    } else {
        Extension ext;
        ext.value = ""_L1;
        ext.critical = false;
        return ext;
    }
}

QString LdapUrl::extension(const QString &key, bool &critical) const
{
    const Extension ext = extension(key);
    critical = ext.critical;
    return ext.value;
}

void LdapUrl::setExtension(const QString &key, const LdapUrl::Extension &ext)
{
    d->m_extensions[key] = ext;
    updateQuery();
}

void LdapUrl::setExtension(const QString &key, const QString &value, bool critical)
{
    Extension ext;
    ext.value = value;
    ext.critical = critical;
    setExtension(key, ext);
}

void LdapUrl::setExtension(const QString &key, int value, bool critical)
{
    Extension ext;
    ext.value = QString::number(value);
    ext.critical = critical;
    setExtension(key, ext);
}

void LdapUrl::removeExtension(const QString &key)
{
    d->m_extensions.remove(key);
    updateQuery();
}

void LdapUrl::updateQuery()
{
    QMap<QString, Extension>::const_iterator it;
    QString q(u'?');

    // set the attributes to query
    if (!d->m_attributes.isEmpty()) {
        q += d->m_attributes.join(u',');
    }

    // set the scope
    q += u'?';
    switch (d->m_scope) {
    case Sub:
        q += u"sub"_s;
        break;
    case One:
        q += u"one"_s;
        break;
    case Base:
        q += u"base"_s;
        break;
    }

    // set the filter
    q += u'?';
    if (d->m_filter != "(objectClass=*)"_L1 && !d->m_filter.isEmpty()) {
        q += QLatin1StringView(toPercentEncoding(d->m_filter));
    }

    // set the extensions
    q += u'?';
    for (it = d->m_extensions.constBegin(); it != d->m_extensions.constEnd(); ++it) {
        if (it.value().critical) {
            q += u'!';
        }
        q += it.key();
        if (!it.value().value.isEmpty()) {
            q += u'=' + QLatin1StringView(toPercentEncoding(it.value().value));
        }
        q += u',';
    }
    while (q.endsWith(u'?') || q.endsWith(u',')) {
        q.remove(q.length() - 1, 1);
    }

    setQuery(q);
    qCDebug(LDAP_CORE_LOG) << "LDAP URL updateQuery():" << toDisplayString();
}

void LdapUrl::parseQuery()
{
    Extension ext;
    QStringList extensions;
    QString q = query(QUrl::FullyEncoded);
    // remove first ?
    if (q.startsWith(u'?')) {
        q.remove(0, 1);
    }

    // split into a list
    const QStringList url_items = q.split(u'?');

    d->m_attributes.clear();
    d->m_scope = Base;
    d->m_filter = u"(objectClass=*)"_s;
    d->m_extensions.clear();

    int i = 0;
    QStringList::const_iterator end(url_items.constEnd());
    for (QStringList::const_iterator it = url_items.constBegin(); it != end; ++it, i++) {
        switch (i) {
        case 0:
            d->m_attributes = (*it).split(u',', Qt::SkipEmptyParts);
            break;
        case 1:
            if ((*it) == "sub"_L1) {
                d->m_scope = Sub;
            } else if ((*it) == "one"_L1) {
                d->m_scope = One;
            }
            break;
        case 2:
            d->m_filter = fromPercentEncoding((*it).toLatin1());
            break;
        case 3:
            extensions = (*it).split(u',', Qt::SkipEmptyParts);
            break;
        }
    }

    QString value;
    QStringList::const_iterator end2(extensions.constEnd());
    for (QStringList::const_iterator it = extensions.constBegin(); it != end2; ++it) {
        ext.critical = false;
        QString name = fromPercentEncoding((*it).section(u'=', 0, 0).toLatin1()).toLower();
        value = fromPercentEncoding((*it).section(u'=', 1).toLatin1());
        if (name.startsWith(u'!')) {
            ext.critical = true;
            name.remove(0, 1);
        }
        qCDebug(LDAP_CORE_LOG) << "LdapUrl extensions name=" << name << "value:" << value;
        ext.value = value.replace("%2"_L1, ","_L1);
        setExtension(name, ext);
    }
}
