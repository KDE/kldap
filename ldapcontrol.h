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

#ifndef KLDAP_LDAPCONTROL_H
#define KLDAP_LDAPCONTROL_H

#include <QString>
#include <QList>

#include <kldap.h>

namespace KLDAP {

  /** This class represents an LDAP Control
   */
  class KLDAP_EXPORT LdapControl
  {
    public:
      LdapControl();
      LdapControl( QString &oid, QByteArray &value, bool critical = false );
      
      void setControl( const QString &oid, const QByteArray &value, bool critical = false);

      void setOid( const QString &oid );
      void setValue( const QByteArray &value );
      void setCritical( bool critical );
      QString oid() const;
      QByteArray value() const;
      bool critical() const;
    
      virtual ~LdapControl();

    private:
      
      QString mOid;
      QByteArray mValue;
      bool mCritical;
      
      class LdapControlPrivate;
      LdapControlPrivate *d;
  };

  typedef QList<LdapControl> LdapControls;

}
#endif
