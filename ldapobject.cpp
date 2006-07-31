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

using namespace KLDAP;

QString LdapObject::toString() const
{
  QString result = QString::fromLatin1( "dn: %1\n" ).arg( mDn );
  for ( LdapAttrMap::ConstIterator it = mAttrs.begin(); it != mAttrs.end(); ++it ) {
    QString attr = it.key();
    for ( LdapAttrValue::ConstIterator it2 = (*it).begin(); it2 != (*it).end(); ++it2 ) {
      result += QString::fromUtf8( Ldif::assembleLine( attr, *it2, 76 ) ) + '\n';
    }
  }
  return result;
}

void LdapObject::clear()
{
  mDn.clear();
  mAttrs.clear();
}

void LdapObject::assign( const LdapObject& that )
{
  if ( &that != this ) {
    mDn = that.mDn;
    mAttrs = that.mAttrs;
  }
}
