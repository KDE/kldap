/*
  This file is part of libkldap.
  SPDX-FileCopyrightText: 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "ldapconfigwidget.h"
using namespace Qt::Literals::StringLiterals;

#include "ldapsearch.h"

#include "ldap_widgets_debug.h"
#include <KAuthorized>
#include <KLineEditEventHandler>
#include <KLocalizedString>
#include <KMessageBox>
#include <KPasswordLineEdit>
#include <QComboBox>
#include <QProgressDialog>

#include <QCheckBox>
#include <QFormLayout>
#include <QObject>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>

using namespace KLDAPWidgets;

class Q_DECL_HIDDEN LdapConfigWidget::LdapConfigWidgetPrivate
{
public:
    LdapConfigWidgetPrivate(LdapConfigWidget *parent)
        : mParent(parent)
    {
        mainLayout = new QFormLayout(mParent);
        mainLayout->setContentsMargins(10, 0, 10, 0);
    }

    void setLDAPPort();
    void setLDAPSPort();
    void setAnonymous(bool on);
    void setSimple(bool on);
    void setSASL(bool on);
    void queryDNClicked();
    void queryMechClicked();
    void loadData(KLDAPCore::LdapSearch *search, const KLDAPCore::LdapObject &object);
    void loadResult(KLDAPCore::LdapSearch *search);
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

    QFormLayout *mainLayout = nullptr;
    WinFlags mFeatures = W_ALL;
    bool mCancelled = false;
};

void LdapConfigWidget::LdapConfigWidgetPrivate::initWidget()
{
    if (mFeatures & W_USER) {
        mUser = new QLineEdit(mParent);
        KLineEditEventHandler::catchReturnKey(mUser);
        mUser->setObjectName("kcfg_ldapuser"_L1);

        mainLayout->addRow(i18n("User:"), mUser);
    }

    if (mFeatures & W_BINDDN) {
        mBindDn = new QLineEdit(mParent);
        KLineEditEventHandler::catchReturnKey(mBindDn);
        mBindDn->setObjectName("kcfg_ldapbinddn"_L1);

        mainLayout->addRow(i18n("Bind DN:"), mBindDn);
    }

    if (mFeatures & W_REALM) {
        mRealm = new QLineEdit(mParent);
        KLineEditEventHandler::catchReturnKey(mRealm);
        mRealm->setObjectName("kcfg_ldaprealm"_L1);

        mainLayout->addRow(i18n("Realm:"), mRealm);
    }

    if (mFeatures & W_PASS) {
        mPassword = new KPasswordLineEdit(mParent);
        KLineEditEventHandler::catchReturnKey(mPassword);
        mPassword->setObjectName("kcfg_ldappassword"_L1);
        mPassword->setRevealPasswordMode(KAuthorized::authorize(QStringLiteral("lineedit_reveal_password")) ? KPassword::RevealMode::OnlyNew
                                                                                                            : KPassword::RevealMode::Never);

        mainLayout->addRow(i18n("Password:"), mPassword);
    }

    if (mFeatures & W_HOST) {
        mHost = new QLineEdit(mParent);
        KLineEditEventHandler::catchReturnKey(mHost);
        mHost->setObjectName("kcfg_ldaphost"_L1);
        mParent->connect(mHost, &QLineEdit::textChanged, mParent, &LdapConfigWidget::hostNameChanged);
        mainLayout->addRow(i18n("Host:"), mHost);
    }

    if (mFeatures & W_PORT) {
        mPort = new QSpinBox(mParent);
        mPort->setRange(0, 65535);
        mPort->setObjectName("kcfg_ldapport"_L1);
        mPort->setValue(389);

        mainLayout->addRow(i18n("Port:"), mPort);
    }

    if (mFeatures & W_VER) {
        mVersion = new QSpinBox(mParent);
        mVersion->setRange(2, 3);
        mVersion->setObjectName("kcfg_ldapver"_L1);
        mVersion->setValue(3);
        mainLayout->addRow(i18n("LDAP version:"), mVersion);
    }

    if (mFeatures & W_SIZELIMIT) {
        mSizeLimit = new QSpinBox(mParent);
        mSizeLimit->setRange(0, 9999999);
        mSizeLimit->setObjectName("kcfg_ldapsizelimit"_L1);
        mSizeLimit->setValue(0);
        mSizeLimit->setSpecialValueText(i18nc("default ldap size limit", "Default"));
        mainLayout->addRow(i18n("Size limit:"), mSizeLimit);
    }

    if (mFeatures & W_TIMELIMIT) {
        mTimeLimit = new QSpinBox(mParent);
        mTimeLimit->setRange(0, 9999999);
        mTimeLimit->setObjectName("kcfg_ldaptimelimit"_L1);
        mTimeLimit->setValue(0);
        mTimeLimit->setSuffix(i18n(" sec"));
        mTimeLimit->setSpecialValueText(i18nc("default ldap time limit", "Default"));
        mainLayout->addRow(i18n("Time limit:"), mTimeLimit);
    }

    if (mFeatures & W_PAGESIZE) {
        mPageSize = new QSpinBox(mParent);
        mPageSize->setRange(0, 9999999);
        mPageSize->setObjectName("kcfg_ldappagesize"_L1);
        mPageSize->setValue(0);
        mPageSize->setSpecialValueText(i18n("No paging"));
        mainLayout->addRow(i18n("Page size:"), mPageSize);
    }

    if (mFeatures & W_DN) {
        auto horizontalLayout = new QHBoxLayout;
        mDn = new QLineEdit(mParent);
        KLineEditEventHandler::catchReturnKey(mDn);
        mDn->setObjectName("kcfg_ldapdn"_L1);
        horizontalLayout->addWidget(mDn);

        // without host query doesn't make sense
        if (mHost) {
            auto dnquery = new QPushButton(i18nc("@action:button", "Query Server"), mParent);
            dnquery->setEnabled(false);
            connect(dnquery, &QPushButton::clicked, mParent, [this]() {
                queryDNClicked();
            });
            connect(mDn, &QLineEdit::textChanged, mParent, [dnquery](const QString &text) {
                dnquery->setEnabled(!text.trimmed().isEmpty());
            });
            horizontalLayout->addWidget(dnquery);
        }
        mainLayout->addRow(i18nc("Distinguished Name", "DN:"), horizontalLayout);
    }

    if (mFeatures & W_FILTER) {
        mFilter = new QLineEdit(mParent);
        KLineEditEventHandler::catchReturnKey(mFilter);
        mFilter->setObjectName("kcfg_ldapfilter"_L1);

        mainLayout->addRow(i18n("Filter:"), mFilter);
    }

    if (mFeatures & W_SECBOX) {
        auto btgroup = new QWidget(mParent);
        btgroup->setContentsMargins({0, 0, 0, 0});

        auto hbox = new QHBoxLayout(btgroup);

        mSecNo = new QRadioButton(i18nc("@option:radio set no security", "No"), btgroup);
        mSecNo->setObjectName("kcfg_ldapnosec"_L1);
        hbox->addWidget(mSecNo);
        mSecTLS = new QRadioButton(i18nc("@option:radio use TLS security", "TLS"), btgroup);
        mSecTLS->setObjectName("kcfg_ldaptls"_L1);
        hbox->addWidget(mSecTLS);
        mSecSSL = new QRadioButton(i18nc("@option:radio use SSL security", "SSL"), btgroup);
        mSecSSL->setObjectName("kcfg_ldapssl"_L1);
        hbox->addWidget(mSecSSL);

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
        mainLayout->addRow(i18n("Security:"), btgroup);
    }

    if (mFeatures & W_AUTHBOX) {
        // invisible QWidget for auto-exclusive radiobutton
        auto authbox = new QWidget(mParent);
        authbox->setContentsMargins({0, 0, 0, 0});

        auto hbox = new QHBoxLayout(authbox);

        mAnonymous = new QRadioButton(i18nc("@option:radio anonymous authentication", "Anonymous"), authbox);
        mAnonymous->setObjectName("kcfg_ldapanon"_L1);
        hbox->addWidget(mAnonymous);
        mSimple = new QRadioButton(i18nc("@option:radio simple authentication", "Simple"), authbox);
        mSimple->setObjectName("kcfg_ldapsimple"_L1);
        hbox->addWidget(mSimple);
        mSASL = new QRadioButton(i18nc("@option:radio SASL authentication", "SASL"), authbox);
        mSASL->setObjectName("kcfg_ldapsasl"_L1);
        hbox->addWidget(mSASL);
        mainLayout->addRow(i18n("Authentication:"), authbox);

        hbox = new QHBoxLayout;
        mMech = new QComboBox(mParent);
        mMech->setObjectName("kcfg_ldapsaslmech"_L1);
        mMech->addItem(QStringLiteral("DIGEST-MD5"));
        mMech->addItem(QStringLiteral("GSSAPI"));
        mMech->addItem(QStringLiteral("PLAIN"));
        hbox->addWidget(mMech);

        // without host query doesn't make sense
        if (mHost) {
            mQueryMech = new QPushButton(i18nc("@action:button", "Query Server"), authbox);
            hbox->addWidget(mQueryMech);
            connect(mQueryMech, &QPushButton::clicked, mParent, [this]() {
                queryMechClicked();
            });
        }
        mainLayout->addRow(i18n("SASL mechanism:"), hbox);

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

void LdapConfigWidget::LdapConfigWidgetPrivate::sendQuery()
{
    KLDAPCore::LdapServer _server(mParent->server());

    mQResult.clear();
    mCancelled = true;

    if (mAttr == "supportedsaslmechanisms"_L1) {
        _server.setAuth(KLDAPCore::LdapServer::Anonymous);
    }

    KLDAPCore::LdapUrl _url(_server.url());

    _url.setDn(KLDAPCore::LdapDN(""_L1));
    _url.setAttributes(QStringList(mAttr));
    _url.setScope(KLDAPCore::LdapUrl::Base);

    qCDebug(LDAP_LOG) << "sendQuery url:" << _url.toDisplayString();

    KLDAPCore::LdapSearch search;
    connect(&search, &KLDAPCore::LdapSearch::data, mParent, [this](KLDAPCore::LdapSearch *s, const KLDAPCore::LdapObject &obj) {
        loadData(s, obj);
    });
    connect(&search, &KLDAPCore::LdapSearch::result, mParent, [this](KLDAPCore::LdapSearch *s) {
        loadResult(s);
    });

    if (!search.search(_url)) {
        KMessageBox::error(mParent, search.errorString(), i18nc("@title:window", "Check server"));
        return;
    }

    if (!mProg) {
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

void LdapConfigWidget::LdapConfigWidgetPrivate::queryMechClicked()
{
    mAttr = QStringLiteral("supportedsaslmechanisms");
    sendQuery();
    if (!mQResult.isEmpty()) {
        mQResult.sort();
        mMech->clear();
        mMech->addItems(mQResult);
    }
}

void LdapConfigWidget::LdapConfigWidgetPrivate::queryDNClicked()
{
    mAttr = QStringLiteral("namingcontexts");
    sendQuery();
    if (!mQResult.isEmpty()) {
        mDn->setText(mQResult.constFirst());
    }
}

void LdapConfigWidget::LdapConfigWidgetPrivate::loadData(KLDAPCore::LdapSearch *, const KLDAPCore::LdapObject &object)
{
    qCDebug(LDAP_LOG) << "object:" << object.toString();
    mProg->setValue(mProg->value() + 1);
    KLDAPCore::LdapAttrMap::ConstIterator end(object.attributes().constEnd());
    for (KLDAPCore::LdapAttrMap::ConstIterator it = object.attributes().constBegin(); it != end; ++it) {
        KLDAPCore::LdapAttrValue::ConstIterator end2((*it).constEnd());
        for (KLDAPCore::LdapAttrValue::ConstIterator it2 = (*it).constBegin(); it2 != end2; ++it2) {
            mQResult.push_back(QString::fromUtf8(*it2));
        }
    }
}

void LdapConfigWidget::LdapConfigWidgetPrivate::loadResult(KLDAPCore::LdapSearch *search)
{
    Q_UNUSED(search)
    mCancelled = false;
    mProg->close();
}

void LdapConfigWidget::LdapConfigWidgetPrivate::setAnonymous(bool on)
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

void LdapConfigWidget::LdapConfigWidgetPrivate::setSimple(bool on)
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

void LdapConfigWidget::LdapConfigWidgetPrivate::setSASL(bool on)
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

void LdapConfigWidget::LdapConfigWidgetPrivate::setLDAPPort()
{
    if (mPort) {
        mPort->setValue(389);
    }
}

void LdapConfigWidget::LdapConfigWidgetPrivate::setLDAPSPort()
{
    if (mPort) {
        mPort->setValue(636);
    }
}

LdapConfigWidget::LdapConfigWidget(QWidget *parent, Qt::WindowFlags fl)
    : QWidget(parent, fl)
    , d(new LdapConfigWidgetPrivate(this))
{
}

LdapConfigWidget::LdapConfigWidget(LdapConfigWidget::WinFlags flags, QWidget *parent, Qt::WindowFlags fl)
    : QWidget(parent, fl)
    , d(new LdapConfigWidgetPrivate(this))
{
    d->mFeatures = flags;

    d->initWidget();
}

LdapConfigWidget::~LdapConfigWidget() = default;

KLDAPCore::LdapUrl LdapConfigWidget::url() const
{
    return server().url();
}

void LdapConfigWidget::setUrl(const KLDAPCore::LdapUrl &url)
{
    KLDAPCore::LdapServer _server;
    _server.setUrl(url);
    setServer(_server);
}

KLDAPCore::LdapServer LdapConfigWidget::server() const
{
    KLDAPCore::LdapServer _server;
    if (d->mSecSSL && d->mSecSSL->isChecked()) {
        _server.setSecurity(KLDAPCore::LdapServer::SSL);
    } else if (d->mSecTLS && d->mSecTLS->isChecked()) {
        _server.setSecurity(KLDAPCore::LdapServer::TLS);
    } else {
        _server.setSecurity(KLDAPCore::LdapServer::None);
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
        _server.setBaseDn(KLDAPCore::LdapDN(d->mDn->text()));
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
        _server.setAuth(KLDAPCore::LdapServer::Anonymous);
    } else if (d->mSimple && d->mSimple->isChecked()) {
        _server.setAuth(KLDAPCore::LdapServer::Simple);
    } else if (d->mSASL && d->mSASL->isChecked()) {
        _server.setAuth(KLDAPCore::LdapServer::SASL);
        _server.setMech(d->mMech->currentText());
    }
    return _server;
}

void LdapConfigWidget::setServer(const KLDAPCore::LdapServer &server)
{
    switch (server.security()) {
    case KLDAPCore::LdapServer::SSL:
        if (d->mSecSSL) {
            d->mSecSSL->setChecked(true);
        }
        break;
    case KLDAPCore::LdapServer::TLS:
        if (d->mSecTLS) {
            d->mSecTLS->setChecked(true);
        }
        break;
    case KLDAPCore::LdapServer::None:
        if (d->mSecNo) {
            d->mSecNo->setChecked(true);
        }
        break;
    }

    switch (server.auth()) {
    case KLDAPCore::LdapServer::Anonymous:
        if (d->mAnonymous) {
            d->mAnonymous->setChecked(true);
        }
        break;
    case KLDAPCore::LdapServer::Simple:
        if (d->mSimple) {
            d->mSimple->setChecked(true);
        }
        break;
    case KLDAPCore::LdapServer::SASL:
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

void LdapConfigWidget::setDn(const KLDAPCore::LdapDN &dn)
{
    if (d->mDn) {
        d->mDn->setText(dn.toString());
    }
}

KLDAPCore::LdapDN LdapConfigWidget::dn() const
{
    return d->mDn ? KLDAPCore::LdapDN(d->mDn->text()) : KLDAPCore::LdapDN();
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
