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

#ifndef KLDAP_LDAPMODELNODE_P_H
#define KLDAP_LDAPMODELNODE_P_H

#include <QByteArray>
#include <QString>
#include <QtCore/QList>
#include <QtCore/QVariant>

#include "ldapdn.h"
#include "ldapobject.h"
#include "kldap_export.h"

namespace KLDAP
{

class LdapModelDNNode;

/**
 * @internal
 */
class LdapModelNode
{
public:
    explicit LdapModelNode(LdapModelDNNode *parent = 0);
    virtual ~LdapModelNode();

    enum NodeType {
        DN,
        Attr
    };

    virtual NodeType nodeType() const = 0;

    LdapModelDNNode *parent();
    int columnCount() const
    {
        return 2;
    }
    int row() const;

    void setPopulated(bool b)
    {
        m_isPopulated = b;
    }
    bool isPopulated() const
    {
        return m_isPopulated;
    }

private:
    LdapModelDNNode *m_parent;
    bool m_isPopulated;
};

/**
 * @internal
 */
class LdapModelDNNode : public LdapModelNode
{
public:
    explicit LdapModelDNNode(LdapModelDNNode *parent = 0,
                             const LdapDN &dn = LdapDN());
    ~LdapModelDNNode();

    LdapModelNode::NodeType nodeType() const
    {
        return LdapModelNode::DN;
    }

    void appendChild(LdapModelNode *pItem);
    LdapModelNode *child(int row);
    int childCount() const
    {
        return m_childItems.size();
    }
    const QList<LdapModelNode *> &children() const
    {
        return m_childItems;
    }

    const LdapDN &dn() const
    {
        return m_dn;
    }

    /**
     * Creates child LdapModelAttrNode object to store \p object's attributes
     * and adds them as children of this node.
     *
     * \param The LdapObject to store in this node.
     */
    void setLdapObject(const LdapObject &object);

private:
    QList<LdapModelNode *> m_childItems;
    LdapDN m_dn;
};

/**
 * @internal
 */
class LdapModelAttrNode : public LdapModelNode
{
public:
    explicit LdapModelAttrNode(LdapModelDNNode *parent = 0,
                               const QString &attrName = QString(),
                               const QByteArray &attrData = QByteArray());
    ~LdapModelAttrNode();

    LdapModelNode::NodeType nodeType() const
    {
        return LdapModelNode::Attr;
    }

    const QString &attributeName()
    {
        return m_attrName;
    }
    const QByteArray &attributeData()
    {
        return m_attrData;
    }

private:
    QString m_attrName;
    QByteArray m_attrData;
};

}

#endif
