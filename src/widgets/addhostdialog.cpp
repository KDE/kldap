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
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QPushButton>
#include <QVBoxLayout>
#include <kldap/ldapconfigwidget.h>
#include <kldap/ldapserver.h>

using namespace KLDAP;
class KLDAP::AddHostDialogPrivate
{
public:
    AddHostDialogPrivate(AddHostDialog *qq)
        : q(qq)
    {
    }

    ~AddHostDialogPrivate()
    {
        writeConfig();
    }

    void readConfig();
    void writeConfig();
    KLDAP::LdapConfigWidget *mCfg = nullptr;
    KLDAP::LdapServer *mServer = nullptr;
    QPushButton *mOkButton = nullptr;
    AddHostDialog *const q;
};

void AddHostDialogPrivate::readConfig()
{
    KConfigGroup group(KSharedConfig::openStateConfig(), "AddHostDialog");
    const QSize size = group.readEntry("Size", QSize(600, 400));
    if (size.isValid()) {
        q->resize(size);
    }
}

void AddHostDialogPrivate::writeConfig()
{
    KConfigGroup group(KSharedConfig::openStateConfig(), "AddHostDialog");
    group.writeEntry("Size", q->size());
    group.sync();
}

AddHostDialog::AddHostDialog(KLDAP::LdapServer *server, QWidget *parent)
    : QDialog(parent)
    , d(new KLDAP::AddHostDialogPrivate(this))
{
    setWindowTitle(i18nc("@title:window", "Add Host"));
    auto mainLayout = new QVBoxLayout(this);
    auto buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    d->mOkButton = buttonBox->button(QDialogButtonBox::Ok);
    d->mOkButton->setDefault(true);
    d->mOkButton->setShortcut(Qt::CTRL | Qt::Key_Return);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &AddHostDialog::reject);

    setModal(true);

    d->mServer = server;

    auto page = new QWidget(this);
    mainLayout->addWidget(page);
    mainLayout->addWidget(buttonBox);
    auto layout = new QHBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);

    d->mCfg = new KLDAP::LdapConfigWidget(KLDAP::LdapConfigWidget::W_USER | KLDAP::LdapConfigWidget::W_PASS | KLDAP::LdapConfigWidget::W_BINDDN
                                              | KLDAP::LdapConfigWidget::W_REALM | KLDAP::LdapConfigWidget::W_HOST | KLDAP::LdapConfigWidget::W_PORT
                                              | KLDAP::LdapConfigWidget::W_VER | KLDAP::LdapConfigWidget::W_TIMELIMIT | KLDAP::LdapConfigWidget::W_SIZELIMIT
                                              | KLDAP::LdapConfigWidget::W_PAGESIZE | KLDAP::LdapConfigWidget::W_DN | KLDAP::LdapConfigWidget::W_FILTER
                                              | KLDAP::LdapConfigWidget::W_SECBOX | KLDAP::LdapConfigWidget::W_AUTHBOX,
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
    case KLDAP::LdapServer::TLS:
        d->mCfg->setSecurity(KLDAP::LdapConfigWidget::TLS);
        break;
    case KLDAP::LdapServer::SSL:
        d->mCfg->setSecurity(KLDAP::LdapConfigWidget::SSL);
        break;
    default:
        d->mCfg->setSecurity(KLDAP::LdapConfigWidget::None);
    }

    switch (d->mServer->auth()) {
    case KLDAP::LdapServer::Simple:
        d->mCfg->setAuth(KLDAP::LdapConfigWidget::Simple);
        break;
    case KLDAP::LdapServer::SASL:
        d->mCfg->setAuth(KLDAP::LdapConfigWidget::SASL);
        break;
    default:
        d->mCfg->setAuth(KLDAP::LdapConfigWidget::Anonymous);
    }
    d->mCfg->setMech(d->mServer->mech());

    KAcceleratorManager::manage(this);
    connect(d->mCfg, &KLDAP::LdapConfigWidget::hostNameChanged, this, &AddHostDialog::slotHostEditChanged);
    connect(d->mOkButton, &QPushButton::clicked, this, &AddHostDialog::slotOk);
    d->mOkButton->setEnabled(!d->mServer->host().isEmpty());
    d->readConfig();
}

AddHostDialog::~AddHostDialog()
{
    delete d;
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
    case KLDAP::LdapConfigWidget::TLS:
        d->mServer->setSecurity(KLDAP::LdapServer::TLS);
        break;
    case KLDAP::LdapConfigWidget::SSL:
        d->mServer->setSecurity(KLDAP::LdapServer::SSL);
        break;
    default:
        d->mServer->setSecurity(KLDAP::LdapServer::None);
    }
    switch (d->mCfg->auth()) {
    case KLDAP::LdapConfigWidget::Simple:
        d->mServer->setAuth(KLDAP::LdapServer::Simple);
        break;
    case KLDAP::LdapConfigWidget::SASL:
        d->mServer->setAuth(KLDAP::LdapServer::SASL);
        break;
    default:
        d->mServer->setAuth(KLDAP::LdapServer::Anonymous);
    }
    d->mServer->setMech(d->mCfg->mech());
    QDialog::accept();
}

#include "moc_addhostdialog.cpp"
