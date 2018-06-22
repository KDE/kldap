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

#ifndef KLDAP_LDAPSTRUCTUREPROXYMODEL_H
#define KLDAP_LDAPSTRUCTUREPROXYMODEL_H

#include <QSortFilterProxyModel>

#include "kldap_export.h"

namespace KLDAP
{

class KLDAP_EXPORT LdapStructureProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    explicit LdapStructureProxyModel(QObject *parent = nullptr);
    ~LdapStructureProxyModel() override;

    Q_REQUIRED_RESULT QVariant data(const QModelIndex &index, int role) const override;
    /**
     * Reimplemented from QAbstractItemModel::setData(). This is a placeholder for when
     * LdapStructureProxyModel beomes writeable and always returns false.
     */
    Q_REQUIRED_RESULT bool setData(const QModelIndex &index,
                 const QVariant &value,
                 int role = Qt::EditRole) override;
    Q_REQUIRED_RESULT bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
    Q_REQUIRED_RESULT QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    Q_REQUIRED_RESULT int columnCount(const QModelIndex &parent) const override;
    Q_REQUIRED_RESULT Qt::ItemFlags flags(const QModelIndex &index) const override;
    Q_REQUIRED_RESULT bool hasChildren(const QModelIndex &parent) const override;

    Q_REQUIRED_RESULT QModelIndex mapFromSource(const QModelIndex &sourceIndex) const override;
    Q_REQUIRED_RESULT QModelIndex mapToSource(const QModelIndex &proxyIndex) const override;

    /**
     * Reimplemented from QAbstractItemModel::insertRows(). This is a placeholder for when
     * LdapStructureProxyModel beomes writeable and always returns false.
     */
    Q_REQUIRED_RESULT bool insertRows(int row, int count,
                    const QModelIndex &parent = QModelIndex()) override;
    /**
     * Reimplemented from QAbstractItemModel::removeRows(). This is a placeholder for when
     * LdapStructureProxyModel beomes writeable and always returns false.
     */
    Q_REQUIRED_RESULT bool removeRows(int row, int count,
                    const QModelIndex &parent = QModelIndex()) override;
    /**
     * Reimplemented from QAbstractItemModel::removeRows(). The default implementation
     * does nothing.
     */
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;
    //
    // Drag and drop support
    //
    /**
     * Reimplemented from QAbstractItemModel::supportedDropActions(). The default
     * implementation returns Qt::MoveAction.
     */
    Q_REQUIRED_RESULT Qt::DropActions supportedDropActions() const override;
    /**
     * Reimplemented from QAbstractItemModel::mimedata(). This is a placeholder for when
     * LdapStructureProxyModel beomes writeable and always returns 0.
     */
    Q_REQUIRED_RESULT QMimeData *mimeData(const QModelIndexList &indexes) const override;
    /**
     * Reimplemented from QAbstractItemModel::dropMimedata(). This is a placeholder for when
     * LdapStructureProxyModel beomes writeable and always returns false.
     */
    Q_REQUIRED_RESULT bool dropMimeData(const QMimeData *data, Qt::DropAction action,
                      int row, int column, const QModelIndex &parent) override;
};

}
#endif
