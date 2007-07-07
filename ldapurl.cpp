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

#include "ldapurl.h"

#include <kdebug.h>

#include <QtCore/QDir>
#include <QtCore/QStringList>

using namespace KLDAP;

class LdapUrl::LdapUrlPrivate
{
  public:
    LdapUrlPrivate()
      : m_scope( Base )
    {
    }

    QMap<QString, Extension> m_extensions;
    QStringList m_attributes;
    Scope m_scope;
    QString m_filter;
};

LdapUrl::LdapUrl()
  : d( new LdapUrlPrivate )
{
}

LdapUrl::LdapUrl( const KUrl &_url )
  : KUrl( _url ), d( new LdapUrlPrivate )
{
  QString tmp = path();
  if ( !QDir::isRelativePath( tmp ) )
#ifdef Q_OS_WIN
    tmp.remove( 0, 3 ); // e.g. "c:/"
#else
    tmp.remove( 0, 1 );
#endif
  setPath( tmp );
  parseQuery();
}

LdapUrl::LdapUrl( const LdapUrl &that )
  : KUrl( that ), d( new LdapUrlPrivate )
{
  *d = *that.d;
}

LdapUrl &LdapUrl::operator=( const LdapUrl &that )
{
  if ( this == &that ) {
    return *this;
  }

  KUrl::operator=( that );
  *d = *that.d;

  return *this;
}

LdapUrl::~LdapUrl()
{
  delete d;
}

void LdapUrl::setDn( const LdapDN &dn )
{
  QString tmp = dn.toString();
  if ( !QDir::isRelativePath( tmp ) )
#ifdef Q_OS_WIN
    tmp.remove( 0, 3 ); // e.g. "c:/"
#else
    tmp.remove( 0, 1 );
#endif
  setPath( tmp );
}

LdapDN LdapUrl::dn() const
{
  QString tmp = path();
  if ( !QDir::isRelativePath( tmp ) )
#ifdef Q_OS_WIN
    tmp.remove( 0, 3 ); // e.g. "c:/"
#else
    tmp.remove( 0, 1 );
#endif
  LdapDN tmpDN( tmp );
  return tmpDN;
}

QStringList LdapUrl::attributes() const
{
  return d->m_attributes;
}

void LdapUrl::setAttributes( const QStringList &attributes )
{
  d->m_attributes=attributes;
  updateQuery();
}

LdapUrl::Scope LdapUrl::scope() const
{
  return d->m_scope;
}

void LdapUrl::setScope( Scope scope )
{
  d->m_scope = scope;
  updateQuery();
}

QString LdapUrl::filter() const
{
  return d->m_filter;
}

void LdapUrl::setFilter( const QString &filter )
{
  d->m_filter = filter;
  updateQuery();
}

bool LdapUrl::hasExtension( const QString &key ) const
{
  return d->m_extensions.contains( key );
}

LdapUrl::Extension LdapUrl::extension( const QString &key ) const
{
  QMap<QString, Extension>::const_iterator it;

  it = d->m_extensions.find( key );
  if ( it != d->m_extensions.constEnd() ) {
    return (*it);
  } else {
    Extension ext;
    ext.value = "";
    ext.critical = false;
    return ext;
  }
}

QString LdapUrl::extension( const QString &key, bool &critical ) const
{
  Extension ext;

  ext = extension( key );
  critical = ext.critical;
  return ext.value;
}

void LdapUrl::setExtension( const QString &key, const LdapUrl::Extension &ext )
{
  d->m_extensions[ key ] = ext;
  updateQuery();
}

void LdapUrl::setExtension( const QString &key, const QString &value, bool critical )
{
  Extension ext;
  ext.value = value;
  ext.critical = critical;
  setExtension( key, ext );
}

void LdapUrl::setExtension( const QString &key, int value, bool critical )
{
  Extension ext;
  ext.value = QString::number( value );
  ext.critical = critical;
  setExtension( key, ext );
}

void LdapUrl::removeExtension( const QString &key )
{
  d->m_extensions.remove( key );
  updateQuery();
}

void LdapUrl::updateQuery()
{
  Extension ext;
  QMap<QString, Extension>::const_iterator it;
  QString q = "?";

  // set the attributes to query
  if ( d->m_attributes.count() > 0 ) {
    q += d->m_attributes.join(",");
  }

  // set the scope
  q += '?';
  switch( d->m_scope ) {
    case Sub:
      q += "sub";
      break;
    case One:
      q += "one";
      break;
    case Base:
      q += "base";
      break;
  }

  // set the filter
  q += '?';
  if ( d->m_filter != "(objectClass=*)" && !d->m_filter.isEmpty() ) {
    q += d->m_filter;
  }

  // set the extensions
  q += '?';
  for ( it = d->m_extensions.constBegin(); it != d->m_extensions.constEnd(); ++it ) {
    if ( it.value().critical ) {
      q += '!';
    }
    q += it.key();
    if ( !it.value().value.isEmpty() ) {
      q += '=' + toPercentEncoding(it.value().value);
    }
    q += ',';
  }
  while  ( q.endsWith( '?' ) || q.endsWith( ',' ) ) {
    q.remove( q.length() - 1, 1 );
  }

  setQuery( q );
  kDebug(5322) << "LDAP URL updateQuery(): " << prettyUrl() << endl;
}

void LdapUrl::parseQuery()
{
  Extension ext;
  QStringList extensions;
  QString q = query();
  // remove first ?
  if ( q.startsWith( '?' ) ) {
    q.remove( 0, 1 );
  }

  // split into a list
  QStringList url_items = q.split( '?' );

  d->m_attributes.clear();
  d->m_scope = Base;
  d->m_filter = "(objectClass=*)";
  d->m_extensions.clear();

  int i = 0;
  for ( QStringList::Iterator it = url_items.begin(); it != url_items.end(); ++it, i++ ) {
    switch ( i ) {
      case 0:
        d->m_attributes = (*it).split( ',', QString::SkipEmptyParts );
        break;
      case 1:
        if ( (*it) == "sub" ) {
          d->m_scope = Sub;
        } else if ( (*it) == "one") {
          d->m_scope = One;
        }
        break;
      case 2:
        d->m_filter = fromPercentEncoding( (*it).toLatin1() );
        break;
      case 3:
        extensions = (*it).split( ',', QString::SkipEmptyParts );
        break;
    }
  }

  QString name, value;
  for ( QStringList::Iterator it = extensions.begin(); it != extensions.end(); ++it ) {
    ext.critical = false;
    name = fromPercentEncoding( (*it).section( '=', 0, 0 ).toLatin1() ).toLower();
    value = fromPercentEncoding( (*it).section( '=', 1 ).toLatin1() );
    if ( name.startsWith( '!' ) ) {
      ext.critical = true;
      name.remove( 0, 1 );
    }
    kDebug(5322) << "LdapUrl extensions name= " << name << " value: " << value << endl;
    ext.value = value.replace( "%2", "," );
    setExtension( name, ext );
  }
}
