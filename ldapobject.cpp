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

class LdapObject::LdapObjectPrivate {
  public:
    QString mDn;
    LdapAttrMap mAttrs;
};

LdapObject::LdapObject()
{
  d = new LdapObjectPrivate;
  d->mDn = QString();
}

LdapObject::LdapObject( const QString& dn )
{
  d = new LdapObjectPrivate;
  d->mDn = dn;
}

LdapObject::~LdapObject()
{
  delete d;
}                  

LdapObject::LdapObject( const LdapObject& that )
{
  d = new LdapObjectPrivate;
  d->mDn = that.d->mDn;
  d->mAttrs = that.d->mAttrs;
}
      
LdapObject& LdapObject::operator=( const LdapObject& that ) 
{ 
  if ( this == &that ) return *this;
  d = new LdapObjectPrivate;
  d->mDn = that.d->mDn;
  d->mAttrs = that.d->mAttrs;
  return *this; 
}
            
void LdapObject::setDn( const QString &dn ) 
{ 
  d->mDn = dn; 
}

void LdapObject::setAttributes( const LdapAttrMap &attrs ) 
{ 
  d->mAttrs = attrs; 
}

QString LdapObject::dn() const 
{ 
  return d->mDn; 
}
                                            
LdapAttrMap LdapObject::attributes() const 
{ 
  return d->mAttrs; 
}
                                                
QString LdapObject::toString() const
{
  QString result = QString::fromLatin1( "dn: %1\n" ).arg( d->mDn );
  for ( LdapAttrMap::ConstIterator it = d->mAttrs.begin(); it != d->mAttrs.end(); ++it ) {
    QString attr = it.key();
    for ( LdapAttrValue::ConstIterator it2 = (*it).begin(); it2 != (*it).end(); ++it2 ) {
      result += QString::fromUtf8( Ldif::assembleLine( attr, *it2, 76 ) ) + '\n';
    }
  }
  return result;
}

void LdapObject::clear()
{
  d->mDn.clear();
  d->mAttrs.clear();
}

void LdapObject::setValues( const QString &attributeName, const LdapAttrValue& values )
{
  d->mAttrs[ attributeName ] = values;
}      

LdapAttrValue LdapObject::values( const QString &attributeName ) const
{
  if ( hasAttribute( attributeName ) ) {
    return d->mAttrs.value( attributeName );
  } else {
    return LdapAttrValue();
  }
}

QByteArray LdapObject::value( const QString &attributeName ) const
{
  if ( hasAttribute( attributeName ) ) {
    return d->mAttrs.value( attributeName ).first();
  } else {
    return QByteArray();
  }
}
                                       
bool LdapObject::hasAttribute( const QString &attributeName ) const
{
  return d->mAttrs.contains( attributeName );
}
