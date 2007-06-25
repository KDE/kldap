/*
  This file is part of libkldap.
  Copyright (c) 2006 Sean Harmer <sh@theharmers.co.uk>

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

#include "ldapdn.h"

#include <algorithm>

#include <kdebug.h>

using namespace KLDAP;

class LdapDN::LdapDNPrivate
{
  public:
    LdapDNPrivate() : m_dn() {}
    ~LdapDNPrivate() {}

    bool isValidRDNString( const QString &rdn ) const;
    QStringList splitOnNonEscapedChar( const QString &rdn, const QChar &ch ) const;

    QString m_dn;
};

bool LdapDN::LdapDNPrivate::isValidRDNString( const QString &rdn ) const
{
  kDebug(5322) << "LdapDN::LdapDNPrivate::isValidRDNString(): Testing rdn: " << rdn << endl;

  // If it is a muli-valued rdn, split it into its constituent parts
  QStringList rdnParts = splitOnNonEscapedChar( rdn, QChar( '+' ) );
  if ( rdnParts.size() > 1 ) {
    for ( int i = 0; i < rdnParts.size(); i++ ) {
      if ( !isValidRDNString( rdnParts.at( i ) ) ) {
        return false;
      }
    }
    return true;
  }

  // Split the rdn into the attribute name and value parts
  QStringList components = rdn.split( "=" );

  // We should have exactly two parts
  if ( components.size() != 2 ) {
    return false;
  }

  return true;
}

QStringList LdapDN::LdapDNPrivate::splitOnNonEscapedChar( const QString &str,
                                                          const QChar &ch ) const
{
  QStringList strParts;
  int index = 0;
  int searchFrom = 0;
  int strPartStartIndex = 0;
  while ( ( index = str.indexOf( ch, searchFrom ) ) != -1 ) {
    const QChar prev = str[std::max( 0, index - 1 )];
    if ( prev != QChar( '\\' ) ) {
      // Found a component of a multi-valued RDN
      //kDebug(5322) << "Found " << ch << " at index " << index << endl;
      QString tmp = str.mid( strPartStartIndex, index - strPartStartIndex );
      //kDebug(5322) << "Adding part: " << tmp << endl;
      strParts.append( tmp );
      strPartStartIndex = index + 1;
    }

    searchFrom = index + 1;
  }

  // Add on the part after the last found delimeter
  QString tmp = str.mid( strPartStartIndex );
  //kDebug(5322) << "Adding part: " << tmp << endl;
  strParts.append( tmp );

  return strParts;
}

LdapDN::LdapDN()
  : d( new LdapDNPrivate )
{

}

LdapDN::LdapDN( const QString &dn )
  : d( new LdapDNPrivate )
{
  d->m_dn = dn;
}

LdapDN::LdapDN( const LdapDN &that )
  : d( new LdapDNPrivate )
{
  *d = *that.d;
}

LdapDN &LdapDN::operator=( const LdapDN &that )
{
  if ( this == &that ) {
    return *this;
  }

  *d = *that.d;
  return *this;
}

LdapDN::~LdapDN()
{
  delete d;
}

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

QString LdapDN::toString( int depth ) const
{
  QStringList rdns = d->splitOnNonEscapedChar( d->m_dn, QChar( ',' ) );
  if ( depth >= rdns.size() ) {
    return QString();
  }

  // Construct a DN down to the requested depth
  QString dn;
  for ( int i = depth; i >= 0; i-- ) {
    dn += rdns.at( rdns.size() - 1 - i ) + QString( "," );
    kDebug(5322) << "dn = " << dn << endl;
  }
  dn = dn.left( dn.length() - 1 ); // Strip off the extraneous comma

  return dn;
}

QString LdapDN::rdnString() const
{
  /** \TODO We should move this into the d pointer as we calculate rdns quite a lot */
  QStringList rdns = d->splitOnNonEscapedChar( d->m_dn, QChar( ',' ) );
  return rdns.at( 0 );
}

QString LdapDN::rdnString( int depth ) const
{
  QStringList rdns = d->splitOnNonEscapedChar( d->m_dn, QChar( ',' ) );
  if ( depth >= rdns.size() ) {
    return QString();
  }
  return rdns.at( rdns.size() - 1 - depth );
}

bool LdapDN::isValid() const
{
  kDebug(5322) << "LdapDN::isValid(): Testing dn: " << d->m_dn << endl;

  // Break the string into rdn's
  QStringList rdns = d->splitOnNonEscapedChar( d->m_dn, QChar( ',' ) );

  // Test to see if each rdn is valid
  for ( int i = 0; i < rdns.size(); i++ ) {
    if ( !d->isValidRDNString( rdns.at( i ) ) ) {
      return false;
    }
  }

  return true;
}

int LdapDN::depth() const
{
  QStringList rdns = d->splitOnNonEscapedChar( d->m_dn, QChar( ',' ) );
  return rdns.size();
}

bool LdapDN::operator == ( const LdapDN &rhs ) const
{
  return d->m_dn == rhs.d->m_dn;
}

bool LdapDN::operator != ( const LdapDN &rhs ) const
{
  return d->m_dn != rhs.d->m_dn;
}
