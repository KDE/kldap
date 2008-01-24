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

#include "ldapmodelnode_p.h"

#include <kdebug.h>

using namespace KLDAP;

LdapModelNode::LdapModelNode( LdapModelDNNode *parent )
  : m_parent( parent ),
    m_isPopulated( false )
{
  if ( m_parent ) {
    m_parent->appendChild( this );
  }
}

LdapModelNode::~LdapModelNode()
{

}

LdapModelDNNode *LdapModelNode::parent()
{
  return m_parent;
}

int LdapModelNode::row() const
{
  if ( m_parent ) {
    return m_parent->children().indexOf( const_cast<LdapModelNode*>( this ) );
  }
  return 0;
}

//
// LdapModelDNNode imlpementation
//

LdapModelDNNode::LdapModelDNNode( LdapModelDNNode *parent,
                                  const LdapDN &dn )
  : LdapModelNode( parent ),
    m_childItems(),
    m_dn( dn )
{
  kDebug(5322) << "Creating LdapModelDNNode: DN =" << m_dn.toString();
}

LdapModelDNNode::~LdapModelDNNode()
{
  qDeleteAll( m_childItems );
}

void LdapModelDNNode::appendChild( LdapModelNode *pItem )
{
  m_childItems.append( pItem );
  setPopulated( true );
}

LdapModelNode *LdapModelDNNode::child( int row )
{
  return m_childItems.value( row );
}

void LdapModelDNNode::setLdapObject( const LdapObject &object )
{
  // Remember whether this item is populated or not
  bool populated = isPopulated();

  const LdapAttrMap &attrs = object.attributes();
  /*
  int attributeCount = 0;
  for ( LdapAttrMap::ConstIterator it = attrs.begin(); it != attrs.end(); ++it ) {
    attributeCount += (*it).size();
  }

  for ( int i = 0; i < attributeCount; i++ )
  {
    LdapModelNode* node = new LdapModelAttrNode( this, QString::number( i ) );
    Q_UNUSED( node );
  }
  */

  for ( LdapAttrMap::ConstIterator it = attrs.begin(); it != attrs.end(); ++it ) {
    QString attr = it.key();
    for ( LdapAttrValue::ConstIterator it2 = (*it).begin(); it2 != (*it).end(); ++it2 ) {
      LdapModelNode *node = new LdapModelAttrNode( this, attr, *it2 );
      Q_UNUSED( node );
    }
  }

  // Reset the populated flag so that we don't stop the model querying for children
  setPopulated( populated );
}

//
// LdapModelAttrNode imlpementation
//

LdapModelAttrNode::LdapModelAttrNode( LdapModelDNNode *parent,
                                      const QString &attrName,
                                      const QByteArray &attrData )
  : LdapModelNode( parent ),
    m_attrName( attrName ),
    m_attrData( attrData )
{
  kDebug(5322) << "Creating LdapModelAttrNode: Name =" << m_attrName
               << " Data =" << m_attrData;
}

LdapModelAttrNode::~LdapModelAttrNode()
{

}
