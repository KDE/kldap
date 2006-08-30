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

#include "ber.h"

#include <kdebug.h>

#include <kldap_config.h>

#ifdef LDAP_FOUND
#include <ldap.h>
#include <lber.h>
#endif

using namespace KLDAP;

class Ber::BerPrivate {
  public:
#ifdef LDAP_FOUND
    BerElement *mBer;
#endif
};

#ifdef LDAP_FOUND
Ber::Ber()
 : d( new BerPrivate )
{
  d->mBer = ber_alloc_t( LBER_USE_DER );
  Q_ASSERT( d->mBer );
}

Ber::Ber( const QByteArray &value )
 : d( new BerPrivate )
{
  struct berval bv;
  bv.bv_val = (char*) value.data();
  bv.bv_len = value.size();
  d->mBer = ber_init( &bv );
  Q_ASSERT( d->mBer );
}

Ber::~Ber()
{
  ber_free( d->mBer, 1 );
  delete d;
}

Ber::Ber( const Ber& that )
  : d( new BerPrivate )
{
  struct berval *bv;
  if ( ber_flatten( that.d->mBer, &bv ) == 0 ) {
    d->mBer = ber_init( bv );
    ber_bvfree( bv );
  }
}

Ber& Ber::operator=( const Ber& that )
{
  if ( this == &that ) return *this;

  struct berval *bv;
  if ( ber_flatten( that.d->mBer, &bv ) == 0 ) {
    d->mBer = ber_init( bv );
    ber_bvfree( bv );
  }
  return *this;
}

QByteArray Ber::flatten()
{
  QByteArray ret;
  struct berval *bv;
  if ( ber_flatten( d->mBer, &bv ) == 0 ) {
    ret = QByteArray( bv->bv_val, bv->bv_len );
    ber_bvfree( bv );
  }
  return ret;
}

bool Ber::printf( const QString &format, ... )
{
  Q_UNUSED( format );
  return false;
}

bool Ber::scanf( const QString &format, ... )
{
  Q_UNUSED( format );
  return false;
}

#else

Ber::Ber()
{
  kError() << "LDAP support not compiled" << endl;
}

Ber::Ber( const QByteArray & )
{
  kError() << "LDAP support not compiled" << endl;
}

Ber::~Ber()
{
}

Ber::Ber( const Ber&)
{
  kError() << "LDAP support not compiled" << endl;
}

Ber& Ber::operator=( const Ber& that )
{
  if ( this == &that ) return *this;
  kError() << "LDAP support not compiled" << endl;
  return *this;
}

QByteArray Ber::flatten()
{
  kError() << "LDAP support not compiled" << endl;
  return QByteArray();
}

bool Ber::printf( const QString &format, ... )
{
  Q_UNUSED( format );
  kError() << "LDAP support not compiled" << endl;
  return false;
}

bool Ber::scanf( const QString &format, ... )
{
  Q_UNUSED( format );
  kError() << "LDAP support not compiled" << endl;
  return false;
}
#endif
