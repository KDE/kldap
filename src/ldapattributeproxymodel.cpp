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

#include "ldapattributeproxymodel.h"
#include "ldapmodel.h"
#include "ldapmodelnode_p.h"

#include <qdebug.h>
#include <klocalizedstring.h>

using namespace KLDAP;

class LdapAttributeProxyModel::LdapAttributeProxyModelPrivate
{
public:
    LdapAttributeProxyModelPrivate();

};

LdapAttributeProxyModel::LdapAttributeProxyModelPrivate::LdapAttributeProxyModelPrivate()
{

}

LdapAttributeProxyModel::LdapAttributeProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent),
      m_d(new LdapAttributeProxyModelPrivate())
{

}

LdapAttributeProxyModel::~LdapAttributeProxyModel()
{
    delete m_d;
}

QVariant LdapAttributeProxyModel::data(const QModelIndex &index,
                                       int role) const
{
    // Included just in case we decide to do any special presentation of the data
    // at some other point throughout the 4.x series.
    return sourceModel()->data(mapToSource(index), role);
}

bool LdapAttributeProxyModel::setData(const QModelIndex &index,
                                      const QVariant &value,
                                      int role)
{
    Q_UNUSED(index);
    Q_UNUSED(value);
    Q_UNUSED(role);
    return false;
}

bool LdapAttributeProxyModel::filterAcceptsRow(int sourceRow,
        const QModelIndex &sourceParent) const
{
    QModelIndex idx = sourceModel()->index(sourceRow, 0, sourceParent);
    LdapModelNode::NodeType nodeType =
        static_cast<LdapModelNode::NodeType>(
            sourceModel()->data(idx, LdapModel::NodeTypeRole).toUInt());
    return nodeType == LdapModelNode::Attr;
}

QVariant LdapAttributeProxyModel::headerData(int section,
        Qt::Orientation orientation,
        int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        if (section == 0) {
            return QVariant(i18n("Attribute"));
        } else if (section == 1) {
            return QVariant(i18n("Value"));
        }
    }

    return QVariant();
}

int LdapAttributeProxyModel::columnCount(const QModelIndex &/*parent*/) const
{
    return 2;
}

Qt::ItemFlags LdapAttributeProxyModel::flags(const QModelIndex &index) const
{
    // Included so as not to break BC in case we wish to use this later in 4.x
    return sourceModel()->flags(mapToSource(index));
}

bool LdapAttributeProxyModel::hasChildren(const QModelIndex &parent) const
{
    // We need to handle this carefully bacause of the filtering out of attributes
    // and the lazy population approach.
    LdapModel *model = static_cast<LdapModel *>(sourceModel());
    return model->hasChildrenOfType(mapToSource(parent), LdapModel::Attribute);
}

QModelIndex LdapAttributeProxyModel::mapFromSource(const QModelIndex &sourceIndex) const
{
    return QSortFilterProxyModel::mapFromSource(sourceIndex);
}

QModelIndex LdapAttributeProxyModel::mapToSource(const QModelIndex &proxyIndex) const
{
    return QSortFilterProxyModel::mapToSource(proxyIndex);
}

bool LdapAttributeProxyModel::insertRows(int row, int count,
        const QModelIndex &parent)
{
    Q_UNUSED(row);
    Q_UNUSED(count);
    Q_UNUSED(parent);
    return false;
}

bool LdapAttributeProxyModel::removeRows(int row, int count,
        const QModelIndex &parent)
{
    Q_UNUSED(row);
    Q_UNUSED(count);
    Q_UNUSED(parent);
    return false;
}

void LdapAttributeProxyModel::sort(int column, Qt::SortOrder order)
{
    Q_UNUSED(column);
    Q_UNUSED(order);
}

Qt::DropActions LdapAttributeProxyModel::supportedDropActions() const
{
    return Qt::MoveAction;
}

QMimeData *LdapAttributeProxyModel::mimeData(const QModelIndexList &indexes) const
{
    Q_UNUSED(indexes);
    return 0;
}

bool LdapAttributeProxyModel::dropMimeData(const QMimeData *data, Qt::DropAction action,
        int row, int column, const QModelIndex &parent)
{
    /** \todo Implement drag and drop for LdapModel */
    Q_UNUSED(data);
    Q_UNUSED(action);
    Q_UNUSED(row);
    Q_UNUSED(column);
    Q_UNUSED(parent);
    return false;
}

