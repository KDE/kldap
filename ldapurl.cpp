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

#include <QDir>
#include <QStringList>

#include <kdebug.h>

#include "ldapurl.h"

using namespace KLDAP;

LdapUrl::LdapUrl()
{
  m_scope = Base;
}

LdapUrl::LdapUrl(const KUrl &_url)
  : KUrl(_url), m_extensions()
{
  QString tmp = path();
  if ( !QDir::isRelativePath(tmp) )
#ifdef Q_WS_WIN
    tmp.remove(0,3); // e.g. "c:/"
#else
    tmp.remove(0,1);
#endif
  parseQuery();
}

void LdapUrl::setDn( const QString &dn)
{
  QString tmp = dn;
  if ( !QDir::isRelativePath(tmp) )
#ifdef Q_WS_WIN
    tmp.remove(0,3); // e.g. "c:/"
#else
    tmp.remove(0,1);
#endif
  setPath(tmp);
}

QString LdapUrl::dn() const
{
  QString tmp = path();
  if ( !QDir::isRelativePath(tmp) )
#ifdef Q_WS_WIN
    tmp.remove(0,3); // e.g. "c:/"
#else
    tmp.remove(0,1);
#endif
  return tmp;
}

bool LdapUrl::hasExtension( const QString &key ) const
{
  return m_extensions.contains( key );
}

LdapUrl::Extension LdapUrl::extension( const QString &key ) const
{
  QMap<QString, Extension>::const_iterator it;

  it = m_extensions.find( key );
  if ( it != m_extensions.constEnd() )
    return (*it);
  else {
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
  m_extensions[ key ] = ext;
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
  m_extensions.remove( key );
  updateQuery();
}

void LdapUrl::updateQuery()
{
  Extension ext;
  QMap<QString, Extension>::const_iterator it;
  QString q = "?";

  // set the attributes to query
  if ( m_attributes.count() > 0 ) q += m_attributes.join(",");

  // set the scope
  q += '?';
  switch( m_scope ) {
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
  if ( m_filter != "(objectClass=*)" && !m_filter.isEmpty() )
    q += m_filter;

  // set the extensions
  q += '?';
  for ( it = m_extensions.constBegin(); it != m_extensions.constEnd(); ++it ) {
    if ( it.value().critical ) q += '!';
    q += it.key();
    if ( !it.value().value.isEmpty() )
      q += '=' + it.value().value;
    q += ',';
  }
  while  ( q.endsWith("?") || q.endsWith(",") )
    q.remove( q.length() - 1, 1 );

  setQuery(q);
  kDebug(5700) << "LDAP URL updateQuery(): " << prettyUrl() << endl;
}

void LdapUrl::parseQuery()
{
  Extension ext;
  QStringList extensions;
  QString q = query();
  // remove first ?
  if (q.startsWith("?"))
    q.remove(0,1);

  // split into a list
  QStringList url_items = q.split('?');

  m_attributes.clear();
  m_scope = Base;
  m_filter = "(objectClass=*)";
  m_extensions.clear();

  int i = 0;
  for ( QStringList::Iterator it = url_items.begin(); it != url_items.end(); ++it, i++ ) {
    switch (i) {
      case 0:
        m_attributes = (*it).split( ',', QString::SkipEmptyParts );
        break;
      case 1:
        if ( (*it) == "sub" ) m_scope = Sub; else
        if ( (*it) == "one") m_scope = One;
        break;
      case 2:
        m_filter = fromPercentEncoding( (*it).toLatin1() );
        break;
      case 3:
        extensions = (*it).split( ',', QString::SkipEmptyParts );
        break;
    }
  }

  QString name,value;
  for ( QStringList::Iterator it = extensions.begin(); it != extensions.end(); ++it ) {
    ext.critical = false;
    name = fromPercentEncoding( (*it).section('=',0,0).toLatin1() ).toLower();
    value = fromPercentEncoding( (*it).section('=',1).toLatin1() );
    if ( name.startsWith("!") ) {
      ext.critical = true;
      name.remove(0, 1);
    }
    kDebug(5700) << "LdapUrl extensions name= " << name << " value: " << value << endl;
    ext.value = value.replace( "%2", "," );
    setExtension( name, ext );
  }
}
