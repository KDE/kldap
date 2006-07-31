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

using namespace KLDAP;

LdapControl::LdapControl()
{
}

LdapControl::LdapControl( QString &oid, QByteArray &value, bool critical )
{
  setControl( oid, value, critical );
}
            
LdapControl::~LdapControl()
{
}

void LdapControl::setControl( const QString &oid, const QByteArray &value, bool critical )
{
  mOid = oid; mValue = value; mCritical = critical;
}

QString LdapControl::oid() const
{
  return mOid;
}

QByteArray LdapControl::value() const
{
  return mValue;
}

bool LdapControl::critical() const
{
  return mCritical;
}

void LdapControl::setOid( const QString &oid )
{
  mOid = oid;
}

void LdapControl::setValue( const QByteArray &value )
{
  mValue = value;
}

void LdapControl::setCritical( bool critical )
{
  mCritical = critical;
}
