/*
 * SPDX-FileCopyrightText: 2024 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapconfigurewidgetng.h"

#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QTreeView>
#include <QVBoxLayout>

#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>

#include <KLDAPCore/LdapClientSearchConfig>
#include <KLDAPCore/LdapModel>
#include <KLDAPCore/LdapServer>
#include <KLDAPCore/LdapSortProxyModel>

#include "addhostdialog.h"

using namespace KLDAPWidgets;
using namespace Qt::Literals::StringLiterals;

LdapConfigureWidgetNg::LdapConfigureWidgetNg(QWidget *parent)
    : QWidget(parent)
    , mClientSearchConfig(new KLDAPCore::LdapClientSearchConfig)
    , mLdapModel(new KLDAPCore::LdapModel(this))
    , mLdapSortProxyModel(new KLDAPCore::LdapSortProxyModel(this))
{
    mLdapSortProxyModel->setSourceModel(mLdapModel);
    initGUI();
    connect(mHostListView->selectionModel(), &QItemSelectionModel::selectionChanged, this, &LdapConfigureWidgetNg::slotSelectionChanged);
    connect(mHostListView, &QTreeView::doubleClicked, this, &LdapConfigureWidgetNg::slotEditHost);
    connect(mUpButton, &QToolButton::clicked, this, &LdapConfigureWidgetNg::slotMoveUp);
    connect(mDownButton, &QToolButton::clicked, this, &LdapConfigureWidgetNg::slotMoveDown);
}

LdapConfigureWidgetNg::~LdapConfigureWidgetNg()
{
    delete mClientSearchConfig;
}

void LdapConfigureWidgetNg::save()
{
    mLdapModel->save();
}

bool LdapConfigureWidgetNg::enablePlasmaActivities() const
{
    return mLdapSortProxyModel->enablePlasmaActivities();
}

void LdapConfigureWidgetNg::setEnablePlasmaActivities(bool newEnablePlasmaActivities)
{
    mLdapSortProxyModel->setEnablePlasmaActivities(newEnablePlasmaActivities);
}

void LdapConfigureWidgetNg::slotAddHost()
{
    KLDAPCore::LdapServer server;
    KLDAPWidgets::AddHostDialog dlg(&server, this);

    if (dlg.exec() && !server.host().trimmed().isEmpty()) { // krazy:exclude=crashy
        mLdapModel->insertServer(server);
        Q_EMIT changed(true);
    }
}

void LdapConfigureWidgetNg::slotSelectionChanged()
{
    const auto nbItems{mHostListView->selectionModel()->selectedRows().count()};
    bool state = (nbItems >= 1);
    mEditButton->setEnabled(state);
    mRemoveButton->setEnabled(state);

    if (!mHostListView->selectionModel()->hasSelection()) {
        return;
    }
    const QModelIndex index = mHostListView->selectionModel()->selectedRows().constFirst();
    const int initialRow = index.row();
    mUpButton->setEnabled(initialRow != 0);
    mDownButton->setEnabled(initialRow != (mHostListView->model()->rowCount() - 1));
}

void LdapConfigureWidgetNg::slotEditHost()
{
    if (!mHostListView->selectionModel()->hasSelection()) {
        return;
    }
    const QModelIndex index = mHostListView->selectionModel()->selectedRows().constFirst();
    const QModelIndex modelIndex = mHostListView->model()->index(index.row(), KLDAPCore::LdapModel::Server);
    KLDAPCore::LdapServer server = modelIndex.data().value<KLDAPCore::LdapServer>();
    KLDAPWidgets::AddHostDialog dlg(&server, this);
    dlg.setWindowTitle(i18nc("@title:window", "Edit Host"));

    if (dlg.exec() && !server.host().isEmpty()) { // krazy:exclude=crashy
        mHostListView->model()->setData(modelIndex, QVariant::fromValue(server));
        Q_EMIT changed(true);
    }
}
void LdapConfigureWidgetNg::slotRemoveHost()
{
    if (!mHostListView->selectionModel()->hasSelection()) {
        return;
    }
    const QModelIndex index = mHostListView->selectionModel()->selectedRows().constFirst();
    const QModelIndex modelIndex = mHostListView->model()->index(index.row(), KLDAPCore::LdapModel::Server);
    const KLDAPCore::LdapServer server = modelIndex.data().value<KLDAPCore::LdapServer>();
    const int answer = KMessageBox::questionTwoActions(this,
                                                       i18n("Do you want to remove setting for host \"%1\"?", server.host()),
                                                       i18nc("@title:window", "Remove Host"),
                                                       KStandardGuiItem::remove(),
                                                       KStandardGuiItem::cancel());
    if (answer == KMessageBox::SecondaryAction) {
        return;
    }
    mLdapModel->removeServer(index.row());
    Q_EMIT changed(true);
}

void LdapConfigureWidgetNg::slotMoveUp()
{
    if (!mHostListView->selectionModel()->hasSelection()) {
        return;
    }
    const QModelIndex index = mHostListView->selectionModel()->selectedRows().constFirst();
    const int initialRow = index.row();

    if (initialRow == 0) {
        return;
    }

    const QModelIndex modelIndex = mHostListView->model()->index(index.row(), KLDAPCore::LdapModel::Index);

    const QModelIndex previewIndex = mHostListView->model()->index(index.row() - 1, KLDAPCore::LdapModel::Index);
    mHostListView->model()->setData(modelIndex, initialRow - 1);
    mHostListView->model()->setData(previewIndex, initialRow);
    mLdapSortProxyModel->invalidate();
#if 0
    mHostListView->setCurrentItem(above);
    above->setSelected(true);
#endif
    Q_EMIT changed(true);
}

void LdapConfigureWidgetNg::slotMoveDown()
{
    if (!mHostListView->selectionModel()->hasSelection()) {
        return;
    }
    const QModelIndex index = mHostListView->selectionModel()->selectedRows().constFirst();
    const int initialRow = index.row();
    if (initialRow != (mHostListView->model()->rowCount() - 1)) {
        return;
    }
    // TODO mLdapModel->setData(index, initialRow + 1, KLDAPCore::LdapModel::Index);
    // TODO next item
    // const QModelIndex nextIndex = mHostListView->selectionModel()->selectedRows().constFirst();
    // TODO mLdapModel->setData(nextIndex, initialRow, KLDAPCore::LdapModel::Index);

    mLdapSortProxyModel->invalidate();
#if 0

    mHostListView->setCurrentItem(below);
    below->setSelected(true);

#endif
    Q_EMIT changed(true);
}

void LdapConfigureWidgetNg::initGUI()
{
    auto mainLayout = new QVBoxLayout(this);
    mainLayout->setObjectName("layout"_L1);

    // Contents of the QVGroupBox: label and hbox
    auto label = new QLabel(i18nc("@label:textbox", "Check all servers that should be used:"), this);
    mainLayout->addWidget(label);

    auto hBox = new QWidget(this);
    mainLayout->addWidget(hBox);

    auto hBoxHBoxLayout = new QHBoxLayout(hBox);
    hBoxHBoxLayout->setContentsMargins({});
    hBoxHBoxLayout->setSpacing(6);
    // Contents of the hbox: listview and up/down buttons on the right (vbox)
    mHostListView = new QTreeView(hBox);
    mHostListView->setAlternatingRowColors(true);
    // mHostListView->setSelectionMode(SingleSelection);
    mHostListView->setContextMenuPolicy(Qt::CustomContextMenu);
    mHostListView->setSelectionBehavior(QAbstractItemView::SelectRows);
    mHostListView->setRootIsDecorated(false);
    mHostListView->setSortingEnabled(false);
    mHostListView->header()->setSectionsMovable(false);
    mHostListView->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    mHostListView->setModel(mLdapSortProxyModel);
    mHostListView->setColumnHidden(KLDAPCore::LdapModel::Activities, true);
    mHostListView->setColumnHidden(KLDAPCore::LdapModel::Index, true);
    mHostListView->setColumnHidden(KLDAPCore::LdapModel::Server, true);
    mHostListView->header()->hide();

    hBoxHBoxLayout->addWidget(mHostListView);

    auto upDownBox = new QWidget(hBox);
    auto upDownBoxVBoxLayout = new QVBoxLayout(upDownBox);
    upDownBoxVBoxLayout->setContentsMargins({});
    hBoxHBoxLayout->addWidget(upDownBox);
    upDownBoxVBoxLayout->setSpacing(6);
    mUpButton = new QToolButton(upDownBox);
    upDownBoxVBoxLayout->addWidget(mUpButton);
    mUpButton->setIcon(QIcon::fromTheme(QStringLiteral("go-up")));
    mUpButton->setEnabled(false); // b/c no item is selected yet

    mDownButton = new QToolButton(upDownBox);
    upDownBoxVBoxLayout->addWidget(mDownButton);
    mDownButton->setIcon(QIcon::fromTheme(QStringLiteral("go-down")));
    mDownButton->setEnabled(false); // b/c no item is selected yet

    auto spacer = new QWidget(upDownBox);
    upDownBoxVBoxLayout->addWidget(spacer);
    upDownBoxVBoxLayout->setStretchFactor(spacer, 100);

    auto buttons = new QDialogButtonBox(this);
    QPushButton *add = buttons->addButton(i18nc("@action:button", "&Add Host…"), QDialogButtonBox::ActionRole);
    connect(add, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotAddHost);
    mEditButton = buttons->addButton(i18nc("@action:button", "&Edit Host…"), QDialogButtonBox::ActionRole);
    connect(mEditButton, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotEditHost);
    mEditButton->setEnabled(false);
    mRemoveButton = buttons->addButton(i18nc("@action:button", "&Remove Host"), QDialogButtonBox::ActionRole);
    connect(mRemoveButton, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotRemoveHost);
    mRemoveButton->setEnabled(false);

    mainLayout->addWidget(buttons);
}

#include "moc_ldapconfigurewidgetng.cpp"
