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

#include <QtCore/QList>

#include <kdebug.h>

#include <kldap_config.h>

#include <cstdarg>

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

int Ber::printf( const QString &format, ... )
{
  char fmt[2];
  va_list args;
  va_start ( args, format );
  fmt[1] = '\0';
  
  int i = 0, ret = 0;
  while ( i < format.length() ) {
    fmt[0] = format[i].toLatin1();
    switch ( fmt[0] ) {
      case 'b':
      case 'e':
      case 'i': 
        {
          ber_int_t v = va_arg( args, int );
          ret = ber_printf( d->mBer, fmt, v );
          break;
        }
      case 'B':
        {
          //FIXME: QBitArray vould be logical, but how to access the bits?
          QByteArray *B = va_arg( args, QByteArray * );
          int Bc = va_arg( args, int );
          ret = ber_printf( d->mBer, fmt, B->data(), Bc );
          break;
        }
      case 'o':
        {
          QByteArray *o = va_arg( args, QByteArray * );
          ret = ber_printf( d->mBer, fmt, o->data(), o->size() );
          break;
        }
      case 'O':
        {
          QByteArray *O = va_arg( args, QByteArray * );
          struct berval bv;
          bv.bv_val = (char*) O->data();
          bv.bv_len = O->size();
          ret = ber_printf( d->mBer, fmt, &bv );
          break;
        }
        break;
      case 's':
        {
          QByteArray *s = va_arg( args, QByteArray * );
          ret = ber_printf( d->mBer, fmt, s->data() );
          break;
        }
        break;
      case 't':
        {
          unsigned int t = va_arg( args, unsigned int );
          ret = ber_printf( d->mBer, fmt, t );
          break;
        }
        break;
      case 'v':
        {
          QList<QByteArray> *v = va_arg( args, QList<QByteArray> * );
          const char *l[v->count()+1];
          int j;
          for ( j = 0; j < v->count(); j++ ) {
            l[j] = v->at(j).data();
          }
          l[j] = 0;
          ret = ber_printf( d->mBer, fmt, l );
          break;
        }
      case 'V':
        {
          QList<QByteArray> *V = va_arg( args, QList<QByteArray> * );
          struct berval *bv[V->count()+1];
          struct berval bvs[V->count()];
          int j;
          for ( j = 0; j < V->count(); j++ ) {
            bvs[j].bv_val = (char *) V->at(j).data();
            bvs[j].bv_len = V->at(j).size();
            bv[j] = &bvs[j];
          }
          bv[j] = 0;
          ret = ber_printf( d->mBer, fmt, bv );
          break;
        }
      case 'W':
        {
          QList<QByteArray> *W = va_arg( args, QList<QByteArray> * );
          struct berval bvs[W->count()+1];
          int j;
          for ( j = 0; j < W->count(); j++ ) {
            bvs[j].bv_val = (char*) W->at(j).data();
            bvs[j].bv_len = W->at(j).size();
          }
          bvs[j].bv_val = 0;
          ret = ber_printf( d->mBer, fmt, bvs );
          break;
        }
      case 'n':
      case '{':
      case '}':
      case '[':
      case ']':
        ret = ber_printf( d->mBer, fmt );
        break;
      default:
        kWarning() << "Invalid BER format parameter: '" << fmt << "'" << endl;
        ret = -1;
    }
    if ( ret == -1 ) break;
  }
  va_end( args );
  return ret;
}

int Ber::scanf( const QString &format, ... )
{
  Q_UNUSED( format );
  return -1;
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

int Ber::printf( const QString &format, ... )
{
  Q_UNUSED( format );
  kError() << "LDAP support not compiled" << endl;
  return -1;
}

int Ber::scanf( const QString &format, ... )
{
  Q_UNUSED( format );
  kError() << "LDAP support not compiled" << endl;
  return -1;
}
#endif
