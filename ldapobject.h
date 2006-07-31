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

#ifndef KLDAP_LDAPOBJECT_H
#define KLDAP_LDAPOBJECT_H

#include <QString>
#include <QList>
#include <QMap>

#include <kldap.h>

namespace KLDAP {

  typedef QList<QByteArray> LdapAttrValue;
  typedef QMap<QString,LdapAttrValue > LdapAttrMap;

  /** This class represents an LDAP Object
   */
  class KLDAP_EXPORT LdapObject
  {
    public:
      LdapObject()
            : mDn( QString() ) {}
      explicit LdapObject( const QString& dn ) : mDn( dn ) {}
      LdapObject( const LdapObject& that ) { assign( that ); }
                    
      LdapObject& operator=( const LdapObject& that ) { assign( that ); return *this; }
                                            
      QString toString() const;
                                             
      void clear();
      
      void setDn( const QString &dn ) { mDn = dn; }
      void setAttributes( const LdapAttrMap &attrs ) { mAttrs = attrs; }
      const QString &dn() const { return mDn; }
      const LdapAttrMap &attributes() const { return mAttrs; }
                                                                 
    protected:
      void assign( const LdapObject& that );
                                                                        
    private:
      QString mDn;
      LdapAttrMap mAttrs;

      class LdapObjectPrivate;
      LdapObjectPrivate *d;

  };
}
#endif
