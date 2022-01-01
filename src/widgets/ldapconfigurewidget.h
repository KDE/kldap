/*
 * SPDX-FileCopyrightText: 2019-2022 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldap_export.h"

#include <QWidget>

class QListWidget;
class QPushButton;
class QToolButton;
class QListWidgetItem;

namespace KLDAP
{
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
    ~LdapConfigureWidget() override;

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
    KLDAP::LdapClientSearchConfig *const mClientSearchConfig;
};
}

