/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapconfigwidget.h"
#include "ldapsearch.h"

#include "ldap_debug.h"
#include <KAuthorized>
#include <KLocalizedString>
#include <KPasswordLineEdit>
#include <QComboBox>
#include <QProgressDialog>
#include <kmessagebox.h>

#include <QCheckBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QObject>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>
using namespace KLDAP;

class Q_DECL_HIDDEN LdapConfigWidget::Private
{
public:
    Private(LdapConfigWidget *parent)
        : mParent(parent)
    {
        mainLayout = new QGridLayout(mParent);
        mainLayout->setContentsMargins({});
    }

    void setLDAPPort();
    void setLDAPSPort();
    void setAnonymous(bool on);
    void setSimple(bool on);
    void setSASL(bool on);
    void queryDNClicked();
    void queryMechClicked();
    void loadData(LdapSearch *search, const LdapObject &object);
    void loadResult(LdapSearch *search);
    void sendQuery();
    void initWidget();

    LdapConfigWidget *const mParent;
    QStringList mQResult;
    QString mAttr;

    QLineEdit *mUser = nullptr;
    KPasswordLineEdit *mPassword = nullptr;
    QLineEdit *mHost = nullptr;
    QSpinBox *mPort = nullptr;
    QSpinBox *mVersion = nullptr;
    QSpinBox *mSizeLimit = nullptr;
    QSpinBox *mTimeLimit = nullptr;
    QSpinBox *mPageSize = nullptr;
    QLineEdit *mDn = nullptr;
    QLineEdit *mBindDn = nullptr;
    QLineEdit *mRealm = nullptr;
    QLineEdit *mFilter = nullptr;
    QRadioButton *mAnonymous = nullptr;
    QRadioButton *mSimple = nullptr;
    QRadioButton *mSASL = nullptr;
    QCheckBox *mSubTree = nullptr;
    QPushButton *mEditButton = nullptr;
    QPushButton *mQueryMech = nullptr;
    QRadioButton *mSecNo = nullptr;
    QRadioButton *mSecTLS = nullptr;
    QRadioButton *mSecSSL = nullptr;
    QComboBox *mMech = nullptr;

    QProgressDialog *mProg = nullptr;

    QGridLayout *mainLayout = nullptr;
    WinFlags mFeatures = W_ALL;
    bool mCancelled = false;
};

void LdapConfigWidget::Private::initWidget()
{
    QLabel *label = nullptr;

    mUser = mHost = mDn = mBindDn = mRealm = mFilter = nullptr;
    mPassword = nullptr;
    mPort = mVersion = mTimeLimit = mSizeLimit = nullptr;
    mAnonymous = mSimple = mSASL = mSecNo = mSecTLS = mSecSSL = nullptr;
    mEditButton = mQueryMech = nullptr;
    mPageSize = nullptr;
    mMech = nullptr;
    int row = 0;
    int col;

    if (mFeatures & W_USER) {
        label = new QLabel(i18n("User:"), mParent);
        mUser = new QLineEdit(mParent);
        mUser->setObjectName(QStringLiteral("kcfg_ldapuser"));

        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mUser, row, 1, 1, 3);
        row++;
    }

    if (mFeatures & W_BINDDN) {
        label = new QLabel(i18n("Bind DN:"), mParent);
        mBindDn = new QLineEdit(mParent);
        mBindDn->setObjectName(QStringLiteral("kcfg_ldapbinddn"));

        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mBindDn, row, 1, 1, 3);
        row++;
    }

    if (mFeatures & W_REALM) {
        label = new QLabel(i18n("Realm:"), mParent);
        mRealm = new QLineEdit(mParent);
        mRealm->setObjectName(QStringLiteral("kcfg_ldaprealm"));

        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mRealm, row, 1, 1, 3);
        row++;
    }

    if (mFeatures & W_PASS) {
        label = new QLabel(i18n("Password:"), mParent);
        mPassword = new KPasswordLineEdit(mParent);
        mPassword->setObjectName(QStringLiteral("kcfg_ldappassword"));
        mPassword->setRevealPasswordAvailable(KAuthorized::authorize(QStringLiteral("lineedit_reveal_password")));

        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mPassword, row, 1, 1, 3);
        row++;
    }

    if (mFeatures & W_HOST) {
        label = new QLabel(i18n("Host:"), mParent);
        mHost = new QLineEdit(mParent);
        mHost->setObjectName(QStringLiteral("kcfg_ldaphost"));
        mParent->connect(mHost, &QLineEdit::textChanged, mParent, &LdapConfigWidget::hostNameChanged);
        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mHost, row, 1, 1, 3);
        row++;
    }

    col = 0;
    if (mFeatures & W_PORT) {
        label = new QLabel(i18n("Port:"), mParent);
        mPort = new QSpinBox(mParent);
        mPort->setRange(0, 65535);
        mPort->setObjectName(QStringLiteral("kcfg_ldapport"));
        mPort->setSizePolicy(QSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred));
        mPort->setValue(389);

        mainLayout->addWidget(label, row, col);
        mainLayout->addWidget(mPort, row, col + 1);
        col += 2;
    }

    if (mFeatures & W_VER) {
        label = new QLabel(i18n("LDAP version:"), mParent);
        mVersion = new QSpinBox(mParent);
        mVersion->setRange(2, 3);
        mVersion->setObjectName(QStringLiteral("kcfg_ldapver"));
        mVersion->setSizePolicy(QSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred));
        mVersion->setValue(3);
        mainLayout->addWidget(label, row, col);
        mainLayout->addWidget(mVersion, row, col + 1);
    }
    if (mFeatures & (W_PORT | W_VER)) {
        row++;
    }

    col = 0;
    if (mFeatures & W_SIZELIMIT) {
        label = new QLabel(i18n("Size limit:"), mParent);
        mSizeLimit = new QSpinBox(mParent);
        mSizeLimit->setRange(0, 9999999);
        mSizeLimit->setObjectName(QStringLiteral("kcfg_ldapsizelimit"));
        mSizeLimit->setSizePolicy(QSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred));
        mSizeLimit->setValue(0);
        mSizeLimit->setSpecialValueText(i18nc("default ldap size limit", "Default"));
        mainLayout->addWidget(label, row, col);
        mainLayout->addWidget(mSizeLimit, row, col + 1);
        col += 2;
    }

    if (mFeatures & W_TIMELIMIT) {
        label = new QLabel(i18n("Time limit:"), mParent);
        mTimeLimit = new QSpinBox(mParent);
        mTimeLimit->setRange(0, 9999999);
        mTimeLimit->setObjectName(QStringLiteral("kcfg_ldaptimelimit"));
        mTimeLimit->setSizePolicy(QSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred));
        mTimeLimit->setValue(0);
        mTimeLimit->setSuffix(i18n(" sec"));
        mTimeLimit->setSpecialValueText(i18nc("default ldap time limit", "Default"));
        mainLayout->addWidget(label, row, col);
        mainLayout->addWidget(mTimeLimit, row, col + 1);
    }
    if (mFeatures & (W_SIZELIMIT | W_TIMELIMIT)) {
        row++;
    }

    if (mFeatures & W_PAGESIZE) {
        label = new QLabel(i18n("Page size:"), mParent);
        mPageSize = new QSpinBox(mParent);
        mPageSize->setRange(0, 9999999);
        mPageSize->setObjectName(QStringLiteral("kcfg_ldappagesize"));
        mPageSize->setSizePolicy(QSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred));
        mPageSize->setValue(0);
        mPageSize->setSpecialValueText(i18n("No paging"));
        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mPageSize, row++, 1);
    }

    if (mFeatures & W_DN) {
        label = new QLabel(i18nc("Distinguished Name", "DN:"), mParent);
        mDn = new QLineEdit(mParent);
        mDn->setObjectName(QStringLiteral("kcfg_ldapdn"));

        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mDn, row, 1, 1, 1);
        // without host query doesn't make sense
        if (mHost) {
            auto dnquery = new QPushButton(i18n("Query Server"), mParent);
            dnquery->setEnabled(false);
            connect(dnquery, &QPushButton::clicked, mParent, [this]() {
                queryDNClicked();
            });
            connect(mDn, &QLineEdit::textChanged, mParent, [dnquery](const QString &text) {
                dnquery->setEnabled(!text.trimmed().isEmpty());
            });
            mainLayout->addWidget(dnquery, row, 2, 1, 1);
        }
        row++;
    }

    if (mFeatures & W_FILTER) {
        label = new QLabel(i18n("Filter:"), mParent);
        mFilter = new QLineEdit(mParent);
        mFilter->setObjectName(QStringLiteral("kcfg_ldapfilter"));

        mainLayout->addWidget(label, row, 0);
        mainLayout->addWidget(mFilter, row, 1, 1, 3);
        row++;
    }

    if (mFeatures & W_SECBOX) {
        auto btgroup = new QGroupBox(i18n("Security"), mParent);
        auto hbox = new QHBoxLayout;
        btgroup->setLayout(hbox);
        mSecNo = new QRadioButton(i18nc("@option:radio set no security", "No"), btgroup);
        mSecNo->setObjectName(QStringLiteral("kcfg_ldapnosec"));
        hbox->addWidget(mSecNo);
        mSecTLS = new QRadioButton(i18nc("@option:radio use TLS security", "TLS"), btgroup);
        mSecTLS->setObjectName(QStringLiteral("kcfg_ldaptls"));
        hbox->addWidget(mSecTLS);
        mSecSSL = new QRadioButton(i18nc("@option:radio use SSL security", "SSL"), btgroup);
        mSecSSL->setObjectName(QStringLiteral("kcfg_ldapssl"));
        hbox->addWidget(mSecSSL);
        mainLayout->addWidget(btgroup, row, 0, 1, 4);

        connect(mSecNo, &QRadioButton::clicked, mParent, [this]() {
            setLDAPPort();
        });
        connect(mSecTLS, &QRadioButton::clicked, mParent, [this]() {
            setLDAPPort();
        });
        connect(mSecSSL, &QRadioButton::clicked, mParent, [this]() {
            setLDAPSPort();
        });

        mSecNo->setChecked(true);
        row++;
    }

    if (mFeatures & W_AUTHBOX) {
        auto authbox = new QGroupBox(i18n("Authentication"), mParent);
        auto vbox = new QVBoxLayout;
        authbox->setLayout(vbox);
        auto hbox = new QHBoxLayout;
        vbox->addLayout(hbox);

        mAnonymous = new QRadioButton(i18nc("@option:radio anonymous authentication", "Anonymous"), authbox);
        mAnonymous->setObjectName(QStringLiteral("kcfg_ldapanon"));
        hbox->addWidget(mAnonymous);
        mSimple = new QRadioButton(i18nc("@option:radio simple authentication", "Simple"), authbox);
        mSimple->setObjectName(QStringLiteral("kcfg_ldapsimple"));
        hbox->addWidget(mSimple);
        mSASL = new QRadioButton(i18nc("@option:radio SASL authentication", "SASL"), authbox);
        mSASL->setObjectName(QStringLiteral("kcfg_ldapsasl"));
        hbox->addWidget(mSASL);

        hbox = new QHBoxLayout;
        vbox->addLayout(hbox);
        label = new QLabel(i18n("SASL mechanism:"), authbox);
        hbox->addWidget(label);
        mMech = new QComboBox(authbox);
        mMech->setObjectName(QStringLiteral("kcfg_ldapsaslmech"));
        mMech->addItem(QStringLiteral("DIGEST-MD5"));
        mMech->addItem(QStringLiteral("GSSAPI"));
        mMech->addItem(QStringLiteral("PLAIN"));
        hbox->addWidget(mMech);

        // without host query doesn't make sense
        if (mHost) {
            mQueryMech = new QPushButton(i18n("Query Server"), authbox);
            hbox->addWidget(mQueryMech);
            connect(mQueryMech, &QPushButton::clicked, mParent, [this]() {
                queryMechClicked();
            });
        }

        mainLayout->addWidget(authbox, row, 0, 2, 4);

        connect(mAnonymous, &QRadioButton::toggled, mParent, [this](bool b) {
            setAnonymous(b);
        });
        connect(mSimple, &QRadioButton::toggled, mParent, [this](bool b) {
            setSimple(b);
        });
        connect(mSASL, &QRadioButton::toggled, mParent, [this](bool b) {
            setSASL(b);
        });

        mAnonymous->setChecked(true);
    }
}

void LdapConfigWidget::Private::sendQuery()
{
    LdapServer _server(mParent->server());

    mQResult.clear();
    mCancelled = true;

    if (mAttr == QLatin1String("supportedsaslmechanisms")) {
        _server.setAuth(LdapServer::Anonymous);
    }

    LdapUrl _url(_server.url());

    _url.setDn(LdapDN(QLatin1String("")));
    _url.setAttributes(QStringList(mAttr));
    _url.setScope(LdapUrl::Base);

    qCDebug(LDAP_LOG) << "sendQuery url:" << _url.toDisplayString();

    LdapSearch search;
    connect(&search, &LdapSearch::data, mParent, [this](KLDAP::LdapSearch *s, const KLDAP::LdapObject &obj) {
        loadData(s, obj);
    });
    connect(&search, &LdapSearch::result, mParent, [this](KLDAP::LdapSearch *s) {
        loadResult(s);
    });

    if (!search.search(_url)) {
        KMessageBox::error(mParent, search.errorString(), i18n("Check server"));
        return;
    }

    if (mProg == nullptr) {
        mProg = new QProgressDialog(mParent);
        mProg->setWindowTitle(i18nc("@title:window", "LDAP Query"));
        mProg->setModal(true);
    }
    mProg->setLabelText(_url.toDisplayString());
    mProg->setMaximum(1);
    mProg->setMinimum(0);
    mProg->setValue(0);
    mProg->exec();
    if (mCancelled) {
        qCDebug(LDAP_LOG) << "query canceled!";
        search.abandon();
    } else {
        if (search.error()) {
            if (search.errorString().isEmpty()) {
                KMessageBox::error(mParent, i18nc("%1 is a url to ldap server", "Unknown error connecting %1", _url.toDisplayString()));
            } else {
                KMessageBox::error(mParent, search.errorString());
            }
        }
    }
}

void LdapConfigWidget::Private::queryMechClicked()
{
    mAttr = QStringLiteral("supportedsaslmechanisms");
    sendQuery();
    if (!mQResult.isEmpty()) {
        mQResult.sort();
        mMech->clear();
        mMech->addItems(mQResult);
    }
}

void LdapConfigWidget::Private::queryDNClicked()
{
    mAttr = QStringLiteral("namingcontexts");
    sendQuery();
    if (!mQResult.isEmpty()) {
        mDn->setText(mQResult.constFirst());
    }
}

void LdapConfigWidget::Private::loadData(LdapSearch *, const LdapObject &object)
{
    qCDebug(LDAP_LOG) << "object:" << object.toString();
    mProg->setValue(mProg->value() + 1);
    LdapAttrMap::ConstIterator end(object.attributes().constEnd());
    for (LdapAttrMap::ConstIterator it = object.attributes().constBegin(); it != end; ++it) {
        LdapAttrValue::ConstIterator end2((*it).constEnd());
        for (LdapAttrValue::ConstIterator it2 = (*it).constBegin(); it2 != end2; ++it2) {
            mQResult.push_back(QString::fromUtf8(*it2));
        }
    }
}

void LdapConfigWidget::Private::loadResult(LdapSearch *search)
{
    Q_UNUSED(search)
    mCancelled = false;
    mProg->close();
}

void LdapConfigWidget::Private::setAnonymous(bool on)
{
    if (!on) {
        return;
    }
    if (mUser) {
        mUser->setEnabled(false);
    }
    if (mPassword) {
        mPassword->setEnabled(false);
    }
    if (mBindDn) {
        mBindDn->setEnabled(false);
    }
    if (mRealm) {
        mRealm->setEnabled(false);
    }
    if (mMech) {
        mMech->setEnabled(false);
    }
    if (mQueryMech) {
        mQueryMech->setEnabled(false);
    }
}

void LdapConfigWidget::Private::setSimple(bool on)
{
    if (!on) {
        return;
    }
    if (mUser) {
        mUser->setEnabled(false);
    }
    if (mPassword) {
        mPassword->setEnabled(true);
    }
    if (mBindDn) {
        mBindDn->setEnabled(true);
    }
    if (mRealm) {
        mRealm->setEnabled(false);
    }
    if (mMech) {
        mMech->setEnabled(false);
    }
    if (mQueryMech) {
        mQueryMech->setEnabled(false);
    }
}

void LdapConfigWidget::Private::setSASL(bool on)
{
    if (!on) {
        return;
    }
    if (mUser) {
        mUser->setEnabled(true);
    }
    if (mPassword) {
        mPassword->setEnabled(true);
    }
    if (mBindDn) {
        mBindDn->setEnabled(true);
    }
    if (mRealm) {
        mRealm->setEnabled(true);
    }
    if (mMech) {
        mMech->setEnabled(true);
    }
    if (mQueryMech) {
        mQueryMech->setEnabled(true);
    }
}

void LdapConfigWidget::Private::setLDAPPort()
{
    if (mPort) {
        mPort->setValue(389);
    }
}

void LdapConfigWidget::Private::setLDAPSPort()
{
    if (mPort) {
        mPort->setValue(636);
    }
}

LdapConfigWidget::LdapConfigWidget(QWidget *parent, Qt::WindowFlags fl)
    : QWidget(parent, fl)
    , d(new Private(this))
{
}

LdapConfigWidget::LdapConfigWidget(LdapConfigWidget::WinFlags flags, QWidget *parent, Qt::WindowFlags fl)
    : QWidget(parent, fl)
    , d(new Private(this))
{
    d->mFeatures = flags;

    d->initWidget();
}

LdapConfigWidget::~LdapConfigWidget()
{
    delete d;
}

LdapUrl LdapConfigWidget::url() const
{
    return server().url();
}

void LdapConfigWidget::setUrl(const LdapUrl &url)
{
    LdapServer _server;
    _server.setUrl(url);
    setServer(_server);
}

LdapServer LdapConfigWidget::server() const
{
    LdapServer _server;
    if (d->mSecSSL && d->mSecSSL->isChecked()) {
        _server.setSecurity(LdapServer::SSL);
    } else if (d->mSecTLS && d->mSecTLS->isChecked()) {
        _server.setSecurity(LdapServer::TLS);
    } else {
        _server.setSecurity(LdapServer::None);
    }

    if (d->mUser) {
        _server.setUser(d->mUser->text());
    }
    if (d->mBindDn) {
        _server.setBindDn(d->mBindDn->text());
    }
    if (d->mPassword) {
        _server.setPassword(d->mPassword->password());
    }
    if (d->mRealm) {
        _server.setRealm(d->mRealm->text());
    }
    if (d->mHost) {
        _server.setHost(d->mHost->text());
    }
    if (d->mPort) {
        _server.setPort(d->mPort->value());
    }
    if (d->mDn) {
        _server.setBaseDn(LdapDN(d->mDn->text()));
    }
    if (d->mFilter) {
        _server.setFilter(d->mFilter->text());
    }
    if (d->mVersion) {
        _server.setVersion(d->mVersion->value());
    }
    if (d->mSizeLimit && d->mSizeLimit->value() != 0) {
        _server.setSizeLimit(d->mSizeLimit->value());
    }
    if (d->mTimeLimit && d->mTimeLimit->value() != 0) {
        _server.setTimeLimit(d->mTimeLimit->value());
    }
    if (d->mPageSize && d->mPageSize->value() != 0) {
        _server.setPageSize(d->mPageSize->value());
    }
    if (d->mAnonymous && d->mAnonymous->isChecked()) {
        _server.setAuth(LdapServer::Anonymous);
    } else if (d->mSimple && d->mSimple->isChecked()) {
        _server.setAuth(LdapServer::Simple);
    } else if (d->mSASL && d->mSASL->isChecked()) {
        _server.setAuth(LdapServer::SASL);
        _server.setMech(d->mMech->currentText());
    }
    return _server;
}

void LdapConfigWidget::setServer(const LdapServer &server)
{
    switch (server.security()) {
    case LdapServer::SSL:
        if (d->mSecSSL) {
            d->mSecSSL->setChecked(true);
        }
        break;
    case LdapServer::TLS:
        if (d->mSecTLS) {
            d->mSecTLS->setChecked(true);
        }
        break;
    case LdapServer::None:
        if (d->mSecNo) {
            d->mSecNo->setChecked(true);
        }
        break;
    }

    switch (server.auth()) {
    case LdapServer::Anonymous:
        if (d->mAnonymous) {
            d->mAnonymous->setChecked(true);
        }
        break;
    case LdapServer::Simple:
        if (d->mSimple) {
            d->mSimple->setChecked(true);
        }
        break;
    case LdapServer::SASL:
        if (d->mSASL) {
            d->mSASL->setChecked(true);
        }
        break;
    }

    setUser(server.user());
    setBindDn(server.bindDn());
    setPassword(server.password());
    setRealm(server.realm());
    setHost(server.host());
    setPort(server.port());
    setFilter(server.filter());
    setDn(server.baseDn());
    setVersion(server.version());
    setSizeLimit(server.sizeLimit());
    setTimeLimit(server.timeLimit());
    setPageSize(server.pageSize());
    setMech(server.mech());
}

void LdapConfigWidget::setUser(const QString &user)
{
    if (d->mUser) {
        d->mUser->setText(user);
    }
}

QString LdapConfigWidget::user() const
{
    return d->mUser ? d->mUser->text() : QString();
}

void LdapConfigWidget::setPassword(const QString &password)
{
    if (d->mPassword) {
        d->mPassword->setPassword(password);
    }
}

QString LdapConfigWidget::password() const
{
    return d->mPassword ? d->mPassword->password() : QString();
}

void LdapConfigWidget::setBindDn(const QString &binddn)
{
    if (d->mBindDn) {
        d->mBindDn->setText(binddn);
    }
}

QString LdapConfigWidget::bindDn() const
{
    return d->mBindDn ? d->mBindDn->text() : QString();
}

void LdapConfigWidget::setRealm(const QString &realm)
{
    if (d->mRealm) {
        d->mRealm->setText(realm);
    }
}

QString LdapConfigWidget::realm() const
{
    return d->mRealm ? d->mRealm->text() : QString();
}

void LdapConfigWidget::setHost(const QString &host)
{
    if (d->mHost) {
        d->mHost->setText(host);
    }
}

QString LdapConfigWidget::host() const
{
    return d->mHost ? d->mHost->text() : QString();
}

void LdapConfigWidget::setPort(int port)
{
    if (d->mPort) {
        d->mPort->setValue(port);
    }
}

int LdapConfigWidget::port() const
{
    return d->mPort ? d->mPort->value() : 389;
}

void LdapConfigWidget::setVersion(int version)
{
    if (d->mVersion) {
        d->mVersion->setValue(version);
    }
}

int LdapConfigWidget::version() const
{
    return d->mVersion ? d->mVersion->value() : 3;
}

void LdapConfigWidget::setDn(const LdapDN &dn)
{
    if (d->mDn) {
        d->mDn->setText(dn.toString());
    }
}

LdapDN LdapConfigWidget::dn() const
{
    return d->mDn ? LdapDN(d->mDn->text()) : LdapDN();
}

void LdapConfigWidget::setFilter(const QString &filter)
{
    if (d->mFilter) {
        d->mFilter->setText(filter);
    }
}

QString LdapConfigWidget::filter() const
{
    return d->mFilter ? d->mFilter->text() : QString();
}

void LdapConfigWidget::setMech(const QString &mech)
{
    if (d->mMech == nullptr) {
        return;
    }
    if (!mech.isEmpty()) {
        int i = 0;
        while (i < d->mMech->count()) {
            if (d->mMech->itemText(i) == mech) {
                break;
            }
            i++;
        }
        if (i == d->mMech->count()) {
            d->mMech->addItem(mech);
        }
        d->mMech->setCurrentIndex(i);
    }
}

QString LdapConfigWidget::mech() const
{
    return d->mMech ? d->mMech->currentText() : QString();
}

void LdapConfigWidget::setSecurity(Security security)
{
    switch (security) {
    case None:
        d->mSecNo->setChecked(true);
        break;
    case SSL:
        d->mSecSSL->setChecked(true);
        break;
    case TLS:
        d->mSecTLS->setChecked(true);
        break;
    }
}

LdapConfigWidget::Security LdapConfigWidget::security() const
{
    if (d->mSecTLS->isChecked()) {
        return TLS;
    }
    if (d->mSecSSL->isChecked()) {
        return SSL;
    }
    return None;
}

void LdapConfigWidget::setAuth(Auth auth)
{
    switch (auth) {
    case Anonymous:
        d->mAnonymous->setChecked(true);
        break;
    case Simple:
        d->mSimple->setChecked(true);
        break;
    case SASL:
        d->mSASL->setChecked(true);
        break;
    }
}

LdapConfigWidget::Auth LdapConfigWidget::auth() const
{
    if (d->mSimple->isChecked()) {
        return Simple;
    }
    if (d->mSASL->isChecked()) {
        return SASL;
    }
    return Anonymous;
}

void LdapConfigWidget::setSizeLimit(int sizelimit)
{
    if (d->mSizeLimit) {
        d->mSizeLimit->setValue(sizelimit);
    }
}

int LdapConfigWidget::sizeLimit() const
{
    return d->mSizeLimit ? d->mSizeLimit->value() : 0;
}

void LdapConfigWidget::setTimeLimit(int timelimit)
{
    if (d->mTimeLimit) {
        d->mTimeLimit->setValue(timelimit);
    }
}

int LdapConfigWidget::timeLimit() const
{
    return d->mTimeLimit ? d->mTimeLimit->value() : 0;
}

void LdapConfigWidget::setPageSize(int pagesize)
{
    if (d->mPageSize) {
        d->mPageSize->setValue(pagesize);
    }
}

int LdapConfigWidget::pageSize() const
{
    return d->mPageSize ? d->mPageSize->value() : 0;
}

LdapConfigWidget::WinFlags LdapConfigWidget::features() const
{
    return d->mFeatures;
}

void LdapConfigWidget::setFeatures(LdapConfigWidget::WinFlags features)
{
    d->mFeatures = features;

    // First delete all the child widgets.
    // FIXME: I hope it's correct
    QList<QObject *> ch = children();
    const int numberOfChild(ch.count());
    for (int i = 0; i < numberOfChild; ++i) {
        QWidget *widget = qobject_cast<QWidget *>(ch[i]);
        if (widget && widget->parent() == this) {
            delete (widget);
        }
    }

    // Re-create child widgets according to the new flags
    d->initWidget();
}

#include "moc_ldapconfigwidget.cpp"
