/*
 * SPDX-FileCopyrightText: 2019-2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldapwidgets_export.h"

#include <QWidget>

class QListWidget;
class QPushButton;
class QToolButton;
class QListWidgetItem;

namespace KLDAPCore
{
class LdapClientSearchConfig;
}

namespace KLDAPWidgets
{
/**
 * @brief The LdapConfigureWidget class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAPWIDGETS_EXPORT LdapConfigureWidget : public QWidget
{
    Q_OBJECT
public:
    explicit LdapConfigureWidget(QWidget *parent = nullptr);
    ~LdapConfigureWidget() override;

    void load();
    void save();

Q_SIGNALS:
    void changed(bool);

private:
    KLDAPWIDGETS_NO_EXPORT void slotAddHost();
    KLDAPWIDGETS_NO_EXPORT void slotEditHost();
    KLDAPWIDGETS_NO_EXPORT void slotRemoveHost();
    KLDAPWIDGETS_NO_EXPORT void slotSelectionChanged(QListWidgetItem *);
    KLDAPWIDGETS_NO_EXPORT void slotItemClicked(QListWidgetItem *);
    KLDAPWIDGETS_NO_EXPORT void slotMoveUp();
    KLDAPWIDGETS_NO_EXPORT void slotMoveDown();
    KLDAPWIDGETS_NO_EXPORT void initGUI();

    QListWidget *mHostListView = nullptr;

    QPushButton *mAddButton = nullptr;
    QPushButton *mEditButton = nullptr;
    QPushButton *mRemoveButton = nullptr;

    QToolButton *mUpButton = nullptr;
    QToolButton *mDownButton = nullptr;
    KLDAPCore::LdapClientSearchConfig *const mClientSearchConfig;
};
}
