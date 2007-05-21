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
#include <qvarlengtharray.h>

#include <kdebug.h>

#include "kldap_config.h"

#include <cstdarg>

#ifdef LDAP_FOUND

#ifdef Q_OS_SOLARIS
#define BC31 1
#endif

#include <lber.h>
#include <ldap.h>

#ifndef LBER_USE_DER
#define LBER_USE_DER 1
#endif

#ifndef ber_memfree
#define ber_memfree(x) ldap_memfree(x)
#endif

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

Ber::Ber( const Ber &that )
  : d( new BerPrivate )
{
  struct berval *bv;
  if ( ber_flatten( that.d->mBer, &bv ) == 0 ) {
    d->mBer = ber_init( bv );
    ber_bvfree( bv );
  }
}

Ber &Ber::operator=( const Ber &that )
{
  if ( this == &that ) {
    return *this;
  }

  struct berval *bv;
  if ( ber_flatten( that.d->mBer, &bv ) == 0 ) {
    d->mBer = ber_init( bv );
    ber_bvfree( bv );
  }
  return *this;
}

QByteArray Ber::flatten() const
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
    i++;
    switch ( fmt[0] ) {
      case 'b':
      case 'e':
      case 'i':
        {
          ber_int_t v = va_arg( args, int );
          kDebug(5322) << fmt << ": " << v << endl;
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
          QVarLengthArray<const char *> l( v->count()+1 );
          int j;
          for ( j = 0; j < v->count(); j++ ) {
            l[j] = v->at(j).data();
          }
          l[j] = 0;
          ret = ber_printf( d->mBer, fmt, l.data() );
          break;
        }
      case 'V':
        {
          QList<QByteArray> *V = va_arg( args, QList<QByteArray> * );
          QVarLengthArray<struct berval *> bv ( V->count()+1 );
          QVarLengthArray<struct berval> bvs( V->count( ) );
          int j;
          for ( j = 0; j < V->count(); j++ ) {
            bvs[j].bv_val = (char *) V->at(j).data();
            bvs[j].bv_len = V->at(j).size();
            bv[j] = &bvs[j];
          }
          bv[V->count()] = 0;
          ret = ber_printf( d->mBer, fmt, bv.data() );
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
    kDebug(5322) << " ber format: " << fmt << " ret: " << ret << endl;
    if ( ret == -1 ) {
      break;
    }
  }
  va_end( args );
  return ret;
}

int Ber::scanf( const QString &format, ... )
{
  char fmt[2];
  va_list args;
  va_start ( args, format );
  fmt[1] = '\0';

  int i = 0, ret = 0;
  while ( i < format.length() ) {
    fmt[0] = format[i].toLatin1();
    i++;
    switch ( fmt[0] ) {
      case 'l':
      case 'b':
      case 'e':
      case 'i':
        {
          int *v = va_arg( args, int * );
          ret = ber_scanf( d->mBer, fmt, v );
          break;
        }
      case 'B':
        {
          //FIXME: QBitArray vould be logical, but how to access the bits?
          QByteArray *B = va_arg( args, QByteArray * );
          int *Bc = va_arg( args, int * );
          char *c;
          ret = ber_scanf( d->mBer, fmt, &c, Bc );
          if ( ret != -1 ) {
            *B = QByteArray( c, ( *Bc + 7 ) / 8 );
            ber_memfree( c );
          }
          break;
        }
      case 'o':
        {
          QByteArray *o = va_arg( args, QByteArray * );
          struct berval bv;
          ret = ber_scanf( d->mBer, fmt, &bv );
          if ( ret != -1 ) {
            *o = QByteArray( bv.bv_val, bv.bv_len );
            ber_memfree( bv.bv_val );
          }
          break;
        }
      case 'O':
        {
          QByteArray *O = va_arg( args, QByteArray * );
          struct berval *bv;
          ret = ber_scanf( d->mBer, fmt, &bv );
          if ( ret != -1 ) {
            *O = QByteArray( bv->bv_val, bv->bv_len );
            ber_bvfree( bv );
          }
          break;
        }
        break;
      case 'm': //the same as 'O', just *bv should not be freed.
        {
          QByteArray *m = va_arg( args, QByteArray * );
          struct berval *bv;
          ret = ber_scanf( d->mBer, fmt, &bv );
          if ( ret != -1 ) {
            *m = QByteArray( bv->bv_val, bv->bv_len );
          }
          break;
        }
      case 'a':
        {
          QByteArray *a = va_arg( args, QByteArray * );
          char *c;
          ret = ber_scanf( d->mBer, fmt, &c );
          if ( ret != -1 ) {
            *a = QByteArray( c );
            ber_memfree( c );
          }
          break;
        }

      case 's':
        {
          QByteArray *s = va_arg( args, QByteArray * );
          char buf[255];
          ber_len_t l = sizeof( buf );
          ret = ber_scanf( d->mBer, fmt, &buf, &l );
          if ( ret != -1 ) {
            *s = QByteArray( buf, l );
          }
          break;
        }
      case 't':
      case 'T':
        {
          unsigned int *t = va_arg( args, unsigned int * );
          ret = ber_scanf( d->mBer, fmt, t );
          break;
        }
        break;
      case 'v':
        {
          QList<QByteArray> *v = va_arg( args, QList<QByteArray> * );
          char **c, **c2;
          ret = ber_scanf( d->mBer, fmt, &c );
          if ( ret != -1 && c ) {
            c2 = c;
            while ( *c ) {
              v->append( QByteArray( *c ) );
              ber_memfree( *c );
              c++;
            }
            ber_memfree( c2 );
          }
          break;
        }
      case 'V':
        {
          QList<QByteArray> *v = va_arg( args, QList<QByteArray> * );
          struct berval **bv, **bv2;
          ret = ber_scanf( d->mBer, fmt, &bv );
          if ( ret != -1 && bv ) {
            bv2 = bv;
            while ( *bv ) {
              v->append( QByteArray( (*bv)->bv_val, (*bv)->bv_len ) );
              bv++;
            }
            ber_bvecfree( bv2 );
          }
          break;
        }
      case 'x':
      case 'n':
      case '{':
      case '}':
      case '[':
      case ']':
        ret = ber_scanf( d->mBer, fmt );
        break;
      default:
        kWarning() << "Invalid BER format parameter: '" << fmt << "'" << endl;
        ret = -1;
    }

    if ( ret == -1 ) {
      break;
    }

  }
  va_end( args );
  return ret;
}

unsigned int Ber::peekTag( int &size )
{
  unsigned int ret;
  ber_len_t len;
  ret = ber_peek_tag( d->mBer, &len );
  size = len;
  return ret;
}

unsigned int Ber::skipTag( int &size )
{
  unsigned int ret;
  ber_len_t len;
  ret = ber_skip_tag( d->mBer, &len );
  size = len;
  return ret;
}
#else

Ber::Ber()
 : d( new BerPrivate )
{
  kError() << "LDAP support not compiled" << endl;
}

Ber::Ber( const QByteArray & )
 : d( new BerPrivate )
{
  kError() << "LDAP support not compiled" << endl;
}

Ber::~Ber()
{
}

Ber::Ber( const Ber&)
 : d( new BerPrivate )
{
  kError() << "LDAP support not compiled" << endl;
}

Ber &Ber::operator=( const Ber &that )
{
  if ( this == &that ) {
    return *this;
  }
  kError() << "LDAP support not compiled" << endl;
  return *this;
}

QByteArray Ber::flatten() const
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

unsigned int Ber::peekTag( int &size )
{
  Q_UNUSED( size );
  kError() << "LDAP support not compiled" << endl;
  return -1;
}

unsigned int Ber::skipTag( int &size )
{
  Q_UNUSED( size );
  kError() << "LDAP support not compiled" << endl;
  return -1;
}

#endif
