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

#include "kldapcore/ldapclientsearchconfig.h"
#include "kldapcore/ldapserver.h"
#include <KLDAPCore/LdapModel>
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
#if 0
    connect(mHostListView, &QListWidget::currentItemChanged, this, &LdapConfigureWidgetNg::slotSelectionChanged);
    connect(mHostListView, &QListWidget::itemDoubleClicked, this, &LdapConfigureWidgetNg::slotEditHost);
    connect(mHostListView, &QListWidget::itemClicked, this, &LdapConfigureWidgetNg::slotItemClicked);

#endif
    connect(mUpButton, &QToolButton::clicked, this, &LdapConfigureWidgetNg::slotMoveUp);
    connect(mDownButton, &QToolButton::clicked, this, &LdapConfigureWidgetNg::slotMoveDown);
}

LdapConfigureWidgetNg::~LdapConfigureWidgetNg()
{
    delete mClientSearchConfig;
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

#if 0
void LdapConfigureWidgetNg::slotSelectionChanged(QListWidgetItem *item)
{
    bool state = (item != nullptr);
    mEditButton->setEnabled(state);
    mRemoveButton->setEnabled(state);
    mDownButton->setEnabled(item && (mHostListView->row(item) != (mHostListView->count() - 1)));
    mUpButton->setEnabled(item && (mHostListView->row(item) != 0));
}

void LdapConfigureWidgetNg::slotItemClicked(QListWidgetItem *item)
{
    auto ldapItem = dynamic_cast<LdapWidgetItem *>(item);
    if (!ldapItem) {
        return;
    }

    if ((ldapItem->checkState() == Qt::Checked) != ldapItem->isActive()) {
        Q_EMIT changed(true);
        ldapItem->setIsActive(ldapItem->checkState() == Qt::Checked);
    }
}
#endif

void LdapConfigureWidgetNg::slotEditHost()
{
#if 0
    auto item = dynamic_cast<LdapWidgetItem *>(mHostListView->currentItem());
    if (!item) {
        return;
    }

    KLDAPCore::LdapServer server = item->server();
    KLDAPWidgets::AddHostDialog dlg(&server, this);
    dlg.setWindowTitle(i18nc("@title:window", "Edit Host"));

    if (dlg.exec() && !server.host().isEmpty()) { // krazy:exclude=crashy
        item->setServer(server);

        Q_EMIT changed(true);
    }
#endif
}
void LdapConfigureWidgetNg::slotRemoveHost()
{
#if 0
    QListWidgetItem *item = mHostListView->currentItem();
    if (!item) {
        return;
    }
    auto ldapItem = static_cast<LdapWidgetItem *>(item);
    const int answer = KMessageBox::questionTwoActions(this,
                                                       i18n("Do you want to remove setting for host \"%1\"?", ldapItem->server().host()),
                                                       i18n("Remove Host"),
                                                       KStandardGuiItem::remove(),
                                                       KStandardGuiItem::cancel());
    if (answer == KMessageBox::SecondaryAction) {
        return;
    }

    delete mHostListView->takeItem(mHostListView->currentRow());

    slotSelectionChanged(mHostListView->currentItem());
#endif
    // TODO mLdapModel->removeServer();
    Q_EMIT changed(true);
}

#if 0
static void swapItems(LdapWidgetItem *item, LdapWidgetItem *other)
{
    KLDAPCore::LdapServer server = item->server();
    bool isActive = item->isActive();
    item->setServer(other->server());
    item->setIsActive(other->isActive());
    item->setCheckState(other->isActive() ? Qt::Checked : Qt::Unchecked);
    other->setServer(server);
    other->setIsActive(isActive);
    other->setCheckState(isActive ? Qt::Checked : Qt::Unchecked);
}
#endif
void LdapConfigureWidgetNg::slotMoveUp()
{
#if 0
    const QList<QListWidgetItem *> selectedItems = mHostListView->selectedItems();
    if (selectedItems.isEmpty()) {
        return;
    }

    LdapWidgetItem *item = static_cast<LdapWidgetItem *>(mHostListView->selectedItems().first());
    if (!item) {
        return;
    }

    auto above = static_cast<LdapWidgetItem *>(mHostListView->item(mHostListView->row(item) - 1));
    if (!above) {
        return;
    }

    swapItems(item, above);

    mHostListView->setCurrentItem(above);
    above->setSelected(true);

#endif
    Q_EMIT changed(true);
}

void LdapConfigureWidgetNg::slotMoveDown()
{
#if 0
    const QList<QListWidgetItem *> selectedItems = mHostListView->selectedItems();
    if (selectedItems.isEmpty()) {
        return;
    }

    LdapWidgetItem *item = static_cast<LdapWidgetItem *>(mHostListView->selectedItems().first());
    if (!item) {
        return;
    }

    auto below = static_cast<LdapWidgetItem *>(mHostListView->item(mHostListView->row(item) + 1));
    if (!below) {
        return;
    }

    swapItems(item, below);

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
    auto label = new QLabel(i18n("Check all servers that should be used:"), this);
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
    mHostListView->setColumnHidden(KLDAPCore::LdapModel::Activities, true);

    hBoxHBoxLayout->addWidget(mHostListView);

    mHostListView->setModel(mLdapModel);

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
    QPushButton *add = buttons->addButton(i18n("&Add Host…"), QDialogButtonBox::ActionRole);
    connect(add, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotAddHost);
    mEditButton = buttons->addButton(i18n("&Edit Host…"), QDialogButtonBox::ActionRole);
    connect(mEditButton, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotEditHost);
    mEditButton->setEnabled(false);
    mRemoveButton = buttons->addButton(i18n("&Remove Host"), QDialogButtonBox::ActionRole);
    connect(mRemoveButton, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotRemoveHost);
    mRemoveButton->setEnabled(false);

    mainLayout->addWidget(buttons);
}

#include "moc_ldapconfigurewidgetng.cpp"
