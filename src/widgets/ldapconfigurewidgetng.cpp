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
#include "ldapclientsearchconfigwriteconfigjob.h"
#include "ldapwidgetitem_p.h"
#include "ldapwidgetitemreadconfigserverjob.h"
#include <KLDAPCore/LdapModel>

#include "addhostdialog.h"

using namespace KLDAPWidgets;
using namespace Qt::Literals::StringLiterals;

LdapConfigureWidgetNg::LdapConfigureWidgetNg(QWidget *parent)
    : QWidget(parent)
    , mClientSearchConfig(new KLDAPCore::LdapClientSearchConfig)
{
    initGUI();
#if 0
    connect(mHostListView, &QListWidget::currentItemChanged, this, &LdapConfigureWidgetNg::slotSelectionChanged);
    connect(mHostListView, &QListWidget::itemDoubleClicked, this, &LdapConfigureWidgetNg::slotEditHost);
    connect(mHostListView, &QListWidget::itemClicked, this, &LdapConfigureWidgetNg::slotItemClicked);

    connect(mUpButton, &QToolButton::clicked, this, &LdapConfigureWidgetNg::slotMoveUp);
    connect(mDownButton, &QToolButton::clicked, this, &LdapConfigureWidgetNg::slotMoveDown);
#endif
}

LdapConfigureWidgetNg::~LdapConfigureWidgetNg()
{
    delete mClientSearchConfig;
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

void LdapConfigureWidgetNg::slotAddHost()
{
    KLDAPCore::LdapServer server;
    KLDAPWidgets::AddHostDialog dlg(&server, this);

    if (dlg.exec() && !server.host().trimmed().isEmpty()) { // krazy:exclude=crashy
        auto item = new LdapWidgetItem(mHostListView);
        item->setServer(server);

        Q_EMIT changed(true);
    }
}

void LdapConfigureWidgetNg::slotEditHost()
{
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
}

void LdapConfigureWidgetNg::slotRemoveHost()
{
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

    Q_EMIT changed(true);
}

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

void LdapConfigureWidgetNg::slotMoveUp()
{
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

    Q_EMIT changed(true);
}

void LdapConfigureWidgetNg::slotMoveDown()
{
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

    Q_EMIT changed(true);
}

void LdapConfigureWidgetNg::load()
{
    mHostListView->clear();
    KConfig *config = KLDAPCore::LdapClientSearchConfig::config();
    KConfigGroup group(config, QStringLiteral("LDAP"));

    int count = group.readEntry("NumSelectedHosts", 0);
    for (int i = 0; i < count; ++i) {
        auto item = new LdapWidgetItem(mHostListView, true);
        item->setCheckState(Qt::Checked);
        auto job = new LdapWidgetItemReadConfigServerJob(this);
        job->setCurrentIndex(i);
        job->setActive(true);
        job->setConfig(group);
        job->setLdapWidgetItem(item);
        job->start();
    }

    count = group.readEntry("NumHosts", 0);
    for (int i = 0; i < count; ++i) {
        auto item = new LdapWidgetItem(mHostListView);
        auto job = new LdapWidgetItemReadConfigServerJob(this);
        job->setCurrentIndex(i);
        job->setActive(false);
        job->setConfig(group);
        job->setLdapWidgetItem(item);
        job->start();
    }

    Q_EMIT changed(false);
}

void LdapConfigureWidgetNg::save()
{
    KConfig *config = KLDAPCore::LdapClientSearchConfig::config();
    config->deleteGroup(QStringLiteral("LDAP"));

    KConfigGroup group(config, QStringLiteral("LDAP"));

    int selected = 0;
    int unselected = 0;
    for (int i = 0; i < mHostListView->count(); ++i) {
        auto item = dynamic_cast<LdapWidgetItem *>(mHostListView->item(i));
        if (!item) {
            continue;
        }

        KLDAPCore::LdapServer server = item->server();
        if (item->checkState() == Qt::Checked) {
            auto job = new KLDAPCore::LdapClientSearchConfigWriteConfigJob;
            job->setActive(true);
            job->setConfig(group);
            job->setServerIndex(selected);
            job->setServer(server);
            job->start();
            selected++;
        } else {
            auto job = new KLDAPCore::LdapClientSearchConfigWriteConfigJob;
            job->setActive(false);
            job->setConfig(group);
            job->setServerIndex(unselected);
            job->setServer(server);
            job->start();
            unselected++;
        }
    }

    group.writeEntry("NumSelectedHosts", selected);
    group.writeEntry("NumHosts", unselected);
    config->sync();

    Q_EMIT changed(false);
}
#endif
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

    hBoxHBoxLayout->addWidget(mHostListView);
    // mHostListView->setSortingEnabled(false);

    auto model = new KLDAPCore::LdapModel(this);
    mHostListView->setModel(model);

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
    // TODO connect(add, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotAddHost);
    mEditButton = buttons->addButton(i18n("&Edit Host…"), QDialogButtonBox::ActionRole);
    // TODO connect(mEditButton, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotEditHost);
    mEditButton->setEnabled(false);
    mRemoveButton = buttons->addButton(i18n("&Remove Host"), QDialogButtonBox::ActionRole);
    // TODO connect(mRemoveButton, &QPushButton::clicked, this, &LdapConfigureWidgetNg::slotRemoveHost);
    mRemoveButton->setEnabled(false);

    mainLayout->addWidget(buttons);
}

#include "moc_ldapconfigurewidgetng.cpp"
