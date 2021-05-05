/*
 * SPDX-FileCopyrightText: 2019-2021 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapconfigurewidget.h"
#include <QGroupBox>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QPushButton>
#include <QToolButton>
#include <QVBoxLayout>

#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>

#include "ldapclientsearch.h"
#include "ldapclientsearchconfig.h"
#include "ldapclientsearchconfigwriteconfigjob.h"
#include "ldapwidgetitem_p.h"
#include "ldapwidgetitemreadconfigserverjob.h"
#include <kldap/ldapserver.h>

#include "addhostdialog.h"

using namespace KLDAP;

LdapConfigureWidget::LdapConfigureWidget(QWidget *parent)
    : QWidget(parent)
{
    mClientSearchConfig = new KLDAP::LdapClientSearchConfig;
    initGUI();

    connect(mHostListView, &QListWidget::currentItemChanged, this, &LdapConfigureWidget::slotSelectionChanged);
    connect(mHostListView, &QListWidget::itemDoubleClicked, this, &LdapConfigureWidget::slotEditHost);
    connect(mHostListView, &QListWidget::itemClicked, this, &LdapConfigureWidget::slotItemClicked);

    connect(mUpButton, &QToolButton::clicked, this, &LdapConfigureWidget::slotMoveUp);
    connect(mDownButton, &QToolButton::clicked, this, &LdapConfigureWidget::slotMoveDown);
}

LdapConfigureWidget::~LdapConfigureWidget()
{
    delete mClientSearchConfig;
}

void LdapConfigureWidget::slotSelectionChanged(QListWidgetItem *item)
{
    bool state = (item != nullptr);
    mEditButton->setEnabled(state);
    mRemoveButton->setEnabled(state);
    mDownButton->setEnabled(item && (mHostListView->row(item) != (mHostListView->count() - 1)));
    mUpButton->setEnabled(item && (mHostListView->row(item) != 0));
}

void LdapConfigureWidget::slotItemClicked(QListWidgetItem *item)
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

void LdapConfigureWidget::slotAddHost()
{
    KLDAP::LdapServer server;
    KLDAP::AddHostDialog dlg(&server, this);

    if (dlg.exec() && !server.host().trimmed().isEmpty()) { // krazy:exclude=crashy
        auto item = new LdapWidgetItem(mHostListView);
        item->setServer(server);

        Q_EMIT changed(true);
    }
}

void LdapConfigureWidget::slotEditHost()
{
    auto item = dynamic_cast<LdapWidgetItem *>(mHostListView->currentItem());
    if (!item) {
        return;
    }

    KLDAP::LdapServer server = item->server();
    KLDAP::AddHostDialog dlg(&server, this);
    dlg.setWindowTitle(i18nc("@title:window", "Edit Host"));

    if (dlg.exec() && !server.host().isEmpty()) { // krazy:exclude=crashy
        item->setServer(server);

        Q_EMIT changed(true);
    }
}

void LdapConfigureWidget::slotRemoveHost()
{
    QListWidgetItem *item = mHostListView->currentItem();
    if (!item) {
        return;
    }
    auto ldapItem = dynamic_cast<LdapWidgetItem *>(item);
    if (KMessageBox::No
        == KMessageBox::questionYesNo(this, i18n("Do you want to remove setting for host \"%1\"?", ldapItem->server().host()), i18n("Remove Host"))) {
        return;
    }

    delete mHostListView->takeItem(mHostListView->currentRow());

    slotSelectionChanged(mHostListView->currentItem());

    Q_EMIT changed(true);
}

static void swapItems(LdapWidgetItem *item, LdapWidgetItem *other)
{
    KLDAP::LdapServer server = item->server();
    bool isActive = item->isActive();
    item->setServer(other->server());
    item->setIsActive(other->isActive());
    item->setCheckState(other->isActive() ? Qt::Checked : Qt::Unchecked);
    other->setServer(server);
    other->setIsActive(isActive);
    other->setCheckState(isActive ? Qt::Checked : Qt::Unchecked);
}

void LdapConfigureWidget::slotMoveUp()
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

void LdapConfigureWidget::slotMoveDown()
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

void LdapConfigureWidget::load()
{
    mHostListView->clear();
    KConfig *config = KLDAP::LdapClientSearchConfig::config();
    KConfigGroup group(config, "LDAP");

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

void LdapConfigureWidget::save()
{
    // mClientSearchConfig->clearWalletPassword();
    KConfig *config = KLDAP::LdapClientSearchConfig::config();
    config->deleteGroup("LDAP");

    KConfigGroup group(config, "LDAP");

    int selected = 0;
    int unselected = 0;
    for (int i = 0; i < mHostListView->count(); ++i) {
        auto item = dynamic_cast<LdapWidgetItem *>(mHostListView->item(i));
        if (!item) {
            continue;
        }

        KLDAP::LdapServer server = item->server();
        if (item->checkState() == Qt::Checked) {
            auto job = new LdapClientSearchConfigWriteConfigJob;
            job->setActive(true);
            job->setConfig(group);
            job->setServerIndex(selected);
            job->setServer(server);
            job->start();
            selected++;
        } else {
            auto job = new LdapClientSearchConfigWriteConfigJob;
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

void LdapConfigureWidget::initGUI()
{
    auto layout = new QVBoxLayout(this);
    layout->setObjectName(QStringLiteral("layout"));
    layout->setContentsMargins(0, 0, 0, 0);

    auto groupBox = new QGroupBox(i18n("LDAP Servers"));
    layout->addWidget(groupBox);
    auto mainLayout = new QVBoxLayout;
    mainLayout->setObjectName(QStringLiteral("mainlayout"));
    groupBox->setLayout(mainLayout);

    // Contents of the QVGroupBox: label and hbox
    auto label = new QLabel(i18n("Check all servers that should be used:"));
    mainLayout->addWidget(label);

    auto hBox = new QWidget(this);
    mainLayout->addWidget(hBox);

    auto hBoxHBoxLayout = new QHBoxLayout(hBox);
    hBoxHBoxLayout->setContentsMargins(0, 0, 0, 0);
    hBoxHBoxLayout->setSpacing(6);
    // Contents of the hbox: listview and up/down buttons on the right (vbox)
    mHostListView = new QListWidget(hBox);
    hBoxHBoxLayout->addWidget(mHostListView);
    mHostListView->setSortingEnabled(false);

    auto upDownBox = new QWidget(hBox);
    auto upDownBoxVBoxLayout = new QVBoxLayout(upDownBox);
    upDownBoxVBoxLayout->setContentsMargins(0, 0, 0, 0);
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
    QPushButton *add = buttons->addButton(i18n("&Add Host..."), QDialogButtonBox::ActionRole);
    connect(add, &QPushButton::clicked, this, &LdapConfigureWidget::slotAddHost);
    mEditButton = buttons->addButton(i18n("&Edit Host..."), QDialogButtonBox::ActionRole);
    connect(mEditButton, &QPushButton::clicked, this, &LdapConfigureWidget::slotEditHost);
    mEditButton->setEnabled(false);
    mRemoveButton = buttons->addButton(i18n("&Remove Host"), QDialogButtonBox::ActionRole);
    connect(mRemoveButton, &QPushButton::clicked, this, &LdapConfigureWidget::slotRemoveHost);
    mRemoveButton->setEnabled(false);
    buttons->layout();

    layout->addWidget(buttons);
}
