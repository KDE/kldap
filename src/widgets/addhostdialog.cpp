/*
  This file is part of libkldap.

  SPDX-FileCopyrightText: 2002-2010 Tobias Koenig <tokoe@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "addhostdialog.h"

#include <KAcceleratorManager>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KWindowConfig>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWindow>
#include <kldapcore/ldapserver.h>
#include <kldapwidgets/ldapconfigwidget.h>

using namespace KLDAPWidgets;
namespace
{
static const char myAddHostDialogPrivateGroupName[] = "AddHostDialog";
}
class KLDAPWidgets::AddHostDialogPrivate
{
public:
    explicit AddHostDialogPrivate(AddHostDialog *qq)
        : q(qq)
    {
    }

    ~AddHostDialogPrivate()
    {
    }

    KLDAPWidgets::LdapConfigWidget *mCfg = nullptr;
    KLDAPCore::LdapServer *mServer = nullptr;
    QPushButton *mOkButton = nullptr;
    AddHostDialog *const q;
};

void AddHostDialog::readConfig()
{
    create(); // ensure a window is created
    windowHandle()->resize(QSize(600, 400));
    KConfigGroup group(KSharedConfig::openStateConfig(), myAddHostDialogPrivateGroupName);
    KWindowConfig::restoreWindowSize(windowHandle(), group);
    resize(windowHandle()->size()); // workaround for QTBUG-40584
}

void AddHostDialog::writeConfig()
{
    KConfigGroup group(KSharedConfig::openStateConfig(), myAddHostDialogPrivateGroupName);
    KWindowConfig::saveWindowSize(windowHandle(), group);
    group.sync();
}

AddHostDialog::AddHostDialog(KLDAPCore::LdapServer *server, QWidget *parent)
    : QDialog(parent)
    , d(new KLDAPWidgets::AddHostDialogPrivate(this))
{
    setWindowTitle(i18nc("@title:window", "Add Host"));
    auto mainLayout = new QVBoxLayout(this);
    auto buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    d->mOkButton = buttonBox->button(QDialogButtonBox::Ok);
    d->mOkButton->setDefault(true);
    d->mOkButton->setShortcut({Qt::CTRL, Qt::Key_Return});
    connect(buttonBox, &QDialogButtonBox::rejected, this, &AddHostDialog::reject);

    setModal(true);

    d->mServer = server;

    auto page = new QWidget(this);
    mainLayout->addWidget(page);
    mainLayout->addWidget(buttonBox);
    auto layout = new QHBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);

    d->mCfg = new KLDAPWidgets::LdapConfigWidget(
        KLDAPWidgets::LdapConfigWidget::W_USER | KLDAPWidgets::LdapConfigWidget::W_PASS | KLDAPWidgets::LdapConfigWidget::W_BINDDN
            | KLDAPWidgets::LdapConfigWidget::W_REALM | KLDAPWidgets::LdapConfigWidget::W_HOST | KLDAPWidgets::LdapConfigWidget::W_PORT
            | KLDAPWidgets::LdapConfigWidget::W_VER | KLDAPWidgets::LdapConfigWidget::W_TIMELIMIT | KLDAPWidgets::LdapConfigWidget::W_SIZELIMIT
            | KLDAPWidgets::LdapConfigWidget::W_PAGESIZE | KLDAPWidgets::LdapConfigWidget::W_DN | KLDAPWidgets::LdapConfigWidget::W_FILTER
            | KLDAPWidgets::LdapConfigWidget::W_SECBOX | KLDAPWidgets::LdapConfigWidget::W_AUTHBOX,
        page);

    layout->addWidget(d->mCfg);
    d->mCfg->setHost(d->mServer->host());
    d->mCfg->setPort(d->mServer->port());
    d->mCfg->setDn(d->mServer->baseDn());
    d->mCfg->setUser(d->mServer->user());
    d->mCfg->setBindDn(d->mServer->bindDn());
    d->mCfg->setPassword(d->mServer->password());
    d->mCfg->setTimeLimit(d->mServer->timeLimit());
    d->mCfg->setSizeLimit(d->mServer->sizeLimit());
    d->mCfg->setPageSize(d->mServer->pageSize());
    d->mCfg->setVersion(d->mServer->version());
    d->mCfg->setFilter(d->mServer->filter());
    switch (d->mServer->security()) {
    case KLDAPCore::LdapServer::TLS:
        d->mCfg->setSecurity(KLDAPWidgets::LdapConfigWidget::TLS);
        break;
    case KLDAPCore::LdapServer::SSL:
        d->mCfg->setSecurity(KLDAPWidgets::LdapConfigWidget::SSL);
        break;
    default:
        d->mCfg->setSecurity(KLDAPWidgets::LdapConfigWidget::None);
    }

    switch (d->mServer->auth()) {
    case KLDAPCore::LdapServer::Simple:
        d->mCfg->setAuth(KLDAPWidgets::LdapConfigWidget::Simple);
        break;
    case KLDAPCore::LdapServer::SASL:
        d->mCfg->setAuth(KLDAPWidgets::LdapConfigWidget::SASL);
        break;
    default:
        d->mCfg->setAuth(KLDAPWidgets::LdapConfigWidget::Anonymous);
    }
    d->mCfg->setMech(d->mServer->mech());

    KAcceleratorManager::manage(this);
    connect(d->mCfg, &KLDAPWidgets::LdapConfigWidget::hostNameChanged, this, &AddHostDialog::slotHostEditChanged);
    connect(d->mOkButton, &QPushButton::clicked, this, &AddHostDialog::slotOk);
    d->mOkButton->setEnabled(!d->mServer->host().isEmpty());
    readConfig();
}

AddHostDialog::~AddHostDialog()
{
    writeConfig();
}

void AddHostDialog::slotHostEditChanged(const QString &text)
{
    d->mOkButton->setEnabled(!text.isEmpty());
}

void AddHostDialog::slotOk()
{
    d->mServer->setHost(d->mCfg->host());
    d->mServer->setPort(d->mCfg->port());
    d->mServer->setBaseDn(d->mCfg->dn());
    d->mServer->setUser(d->mCfg->user());
    d->mServer->setBindDn(d->mCfg->bindDn());
    d->mServer->setPassword(d->mCfg->password());
    d->mServer->setTimeLimit(d->mCfg->timeLimit());
    d->mServer->setSizeLimit(d->mCfg->sizeLimit());
    d->mServer->setPageSize(d->mCfg->pageSize());
    d->mServer->setVersion(d->mCfg->version());
    d->mServer->setFilter(d->mCfg->filter());
    switch (d->mCfg->security()) {
    case KLDAPWidgets::LdapConfigWidget::TLS:
        d->mServer->setSecurity(KLDAPCore::LdapServer::TLS);
        break;
    case KLDAPWidgets::LdapConfigWidget::SSL:
        d->mServer->setSecurity(KLDAPCore::LdapServer::SSL);
        break;
    default:
        d->mServer->setSecurity(KLDAPCore::LdapServer::None);
    }
    switch (d->mCfg->auth()) {
    case KLDAPWidgets::LdapConfigWidget::Simple:
        d->mServer->setAuth(KLDAPCore::LdapServer::Simple);
        break;
    case KLDAPWidgets::LdapConfigWidget::SASL:
        d->mServer->setAuth(KLDAPCore::LdapServer::SASL);
        break;
    default:
        d->mServer->setAuth(KLDAPCore::LdapServer::Anonymous);
    }
    d->mServer->setMech(d->mCfg->mech());
    QDialog::accept();
}

#include "moc_addhostdialog.cpp"
