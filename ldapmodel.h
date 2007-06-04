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

#ifndef KLDAP_LDAPMODEL_H
#define KLDAP_LDAPMODEL_H

#include <QtCore/QAbstractItemModel>

#include "ldapconnection.h"
#include "ldapobject.h"
#include "kldap_export.h"

namespace KLDAP {

class KLDAP_EXPORT LdapModel : public QAbstractItemModel
{
  Q_OBJECT
  public:
    explicit LdapModel( QObject *parent = 0 );
    explicit LdapModel( LdapConnection &connection, QObject *parent = 0 );
    virtual ~LdapModel();

    void setConnection( LdapConnection &connection );

    virtual QModelIndex index( int row, int col, const QModelIndex &parent ) const;
    virtual QModelIndex parent( const QModelIndex &child ) const;
    virtual QVariant data( const QModelIndex &index, int role ) const;
    virtual QVariant headerData( int section, Qt::Orientation orientation, int role ) const;
    virtual Qt::ItemFlags flags( const QModelIndex &index ) const;
    virtual int columnCount( const QModelIndex &parent ) const;
    virtual int rowCount( const QModelIndex &parent ) const;
    virtual bool hasChildren( const QModelIndex &parent ) const;
    virtual bool canFetchMore( const QModelIndex &parent ) const;
    virtual void fetchMore( const QModelIndex &parent );

  private:
    class LdapModelPrivate;
    LdapModelPrivate *const m_d;

    Q_PRIVATE_SLOT( m_d, void gotSearchResult( KLDAP::LdapSearch* ) )
    Q_PRIVATE_SLOT( m_d, void gotSearchData( KLDAP::LdapSearch*, const KLDAP::LdapObject& ) )
};

}
#endif
