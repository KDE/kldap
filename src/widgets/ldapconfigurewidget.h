/*
 * Copyright (C) 2019-2020 Laurent Montel <montel@kde.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef LDAPCONFIGUREWIDGET_H
#define LDAPCONFIGUREWIDGET_H


#include "kldap_export.h"

#include <QWidget>

class QListWidget;
class QPushButton;
class QToolButton;
class QListWidgetItem;

namespace KLDAP {
class LdapClientSearchConfig;
/**
 * @brief The LdapConfigureWidget class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAP_EXPORT LdapConfigureWidget : public QWidget
{
    Q_OBJECT
public:
    explicit LdapConfigureWidget(QWidget *parent = nullptr);
    ~LdapConfigureWidget();

    void load();
    void save();

private Q_SLOTS:
    void slotAddHost();
    void slotEditHost();
    void slotRemoveHost();
    void slotSelectionChanged(QListWidgetItem *);
    void slotItemClicked(QListWidgetItem *);
    void slotMoveUp();
    void slotMoveDown();

Q_SIGNALS:
    void changed(bool);

private:
    void initGUI();

    QListWidget *mHostListView = nullptr;

    QPushButton *mAddButton = nullptr;
    QPushButton *mEditButton = nullptr;
    QPushButton *mRemoveButton = nullptr;

    QToolButton *mUpButton = nullptr;
    QToolButton *mDownButton = nullptr;
    KLDAP::LdapClientSearchConfig *mClientSearchConfig = nullptr;
};
}

#endif // LDAPCONFIGUREWIDGET_H
