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

#ifndef KLDAP_BER_H
#define KLDAP_BER_H

#include <QtCore/QByteArray>

#include <kldap/kldap.h>

namespace KLDAP {

  /**
   * This class allows encoding and decoding Qt structures using Basic Encoding Rules.
   */
  class KLDAP_EXPORT Ber
  {
    public:
      /**
       * Constructs a Ber object.
       */
      Ber();
      /**
       * Constructs a Ber object from the value.
       */
      Ber( const QByteArray &value );
      /**
       * Destroys the Ber object.
       */
      virtual ~Ber();
      /**
       * Returns the Ber object as a flat QByteArray.
       */
      QByteArray flatten();

      bool printf( const QString &format, ... );
      bool scanf( const QString &format, ... );
    private:
      
      class BerPrivate;
      BerPrivate* d;
  };

}
#endif
