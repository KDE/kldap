/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "kldapwidgets_export.h"

#include <QWidget>

class QTreeView;
class QPushButton;
class QToolButton;

namespace KLDAPCore
{
class LdapClientSearchConfig;
class LdapModel;
class LdapSortProxyModel;
}

namespace KLDAPWidgets
{
/**
 * @brief The LdapConfigureWidgetNg class
 * @author Laurent Montel <montel@kde.org>
 */
class KLDAPWIDGETS_EXPORT LdapConfigureWidgetNg : public QWidget
{
    Q_OBJECT
public:
    explicit LdapConfigureWidgetNg(QWidget *parent = nullptr);
    ~LdapConfigureWidgetNg() override;

    void save();

    [[nodiscard]] bool enablePlasmaActivities() const;
    void setEnablePlasmaActivities(bool newEnablePlasmaActivities);

Q_SIGNALS:
    void changed(bool);

private:
    KLDAPWIDGETS_NO_EXPORT void slotAddHost();
    KLDAPWIDGETS_NO_EXPORT void slotEditHost();
    KLDAPWIDGETS_NO_EXPORT void slotRemoveHost();
    KLDAPWIDGETS_NO_EXPORT void slotSelectionChanged();
    KLDAPWIDGETS_NO_EXPORT void slotMoveUp();
    KLDAPWIDGETS_NO_EXPORT void slotMoveDown();
    KLDAPWIDGETS_NO_EXPORT void initGUI();
    QTreeView *mHostListView = nullptr;

    QPushButton *mAddButton = nullptr;
    QPushButton *mEditButton = nullptr;
    QPushButton *mRemoveButton = nullptr;

    QToolButton *mUpButton = nullptr;
    QToolButton *mDownButton = nullptr;
    KLDAPCore::LdapClientSearchConfig *const mClientSearchConfig;
    KLDAPCore::LdapModel *const mLdapModel;
    KLDAPCore::LdapSortProxyModel *const mLdapSortProxyModel;
};
}
