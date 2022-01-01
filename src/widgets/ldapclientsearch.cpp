/* kldapclient.cpp - LDAP access
 * SPDX-FileCopyrightText: 2002 Klarälvdalens Datakonsult AB
 * SPDX-FileContributor: Steffen Hansen <hansen@kde.org>
 *
 * Ported to KABC by Daniel Molkentin <molkentin@kde.org>
 *
 * SPDX-FileCopyrightText: 2013-2022 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearch.h"
#include "ldapclient_debug.h"
#include "ldapclientsearchconfig.h"
#include "ldapsearchclientreadconfigserverjob.h"

#include "ldapclient.h"

#include <kldap/ldapserver.h>
#include <kldap/ldapurl.h>
#include <kldap/ldif.h>

#include <KConfig>
#include <KConfigGroup>
#include <KDirWatch>
#include <KProtocolInfo>
#include <kcoreaddons_version.h>
#if KCOREADDONS_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <Kdelibs4ConfigMigrator>
#endif

#include <KIO/Job>

#include <QStandardPaths>
#include <QTimer>

using namespace KLDAP;

class Q_DECL_HIDDEN LdapClientSearch::LdapClientSearchPrivate
{
public:
    LdapClientSearchPrivate(LdapClientSearch *qq)
        : q(qq)
    {
    }

    ~LdapClientSearchPrivate() = default;

    void readWeighForClient(LdapClient *client, const KConfigGroup &config, int clientNumber);
    void readConfig();
    void finish();
    void makeSearchData(QStringList &ret, LdapResult::List &resList);

    void slotLDAPResult(const KLDAP::LdapClient &client, const KLDAP::LdapObject &);
    void slotLDAPError(const QString &);
    void slotLDAPDone();
    void slotDataTimer();
    void slotFileChanged(const QString &);
    void init(const QStringList &attributes);

    LdapClientSearch *const q;
    QList<LdapClient *> mClients;
    QStringList mAttributes;
    QString mSearchText;
    QString mFilter;
    QTimer mDataTimer;
    int mActiveClients = 0;
    bool mNoLDAPLookup = false;
    LdapResultObject::List mResults;
    QString mConfigFile;
};

LdapClientSearch::LdapClientSearch(QObject *parent)
    : QObject(parent)
    , d(new LdapClientSearchPrivate(this))
{
    d->init(LdapClientSearch::defaultAttributes());
}

LdapClientSearch::LdapClientSearch(const QStringList &attr, QObject *parent)
    : QObject(parent)
    , d(new LdapClientSearchPrivate(this))
{
    d->init(attr);
}

LdapClientSearch::~LdapClientSearch() = default;

void LdapClientSearch::LdapClientSearchPrivate::init(const QStringList &attributes)
{
#if KCOREADDONS_VERSION < QT_VERSION_CHECK(6, 0, 0)
    Kdelibs4ConfigMigrator migrate(QStringLiteral("ldapsettings"));
    migrate.setConfigFiles(QStringList() << QStringLiteral("kabldaprc"));
    migrate.migrate();
#endif

    if (!KProtocolInfo::isKnownProtocol(QUrl(QStringLiteral("ldap://localhost")))) {
        mNoLDAPLookup = true;
        return;
    }

    mAttributes = attributes;

    // Set the filter, to make sure old usage (before 4.14) of this object still works.
    mFilter = QStringLiteral(
        "&(|(objectclass=person)(objectclass=groupOfNames)(mail=*))"
        "(|(cn=%1*)(mail=%1*)(givenName=%1*)(sn=%1*))");

    readConfig();
    q->connect(KDirWatch::self(), &KDirWatch::dirty, q, [this](const QString &filename) {
        slotFileChanged(filename);
    });
}

void LdapClientSearch::LdapClientSearchPrivate::readWeighForClient(LdapClient *client, const KConfigGroup &config, int clientNumber)
{
    const int completionWeight = config.readEntry(QStringLiteral("SelectedCompletionWeight%1").arg(clientNumber), -1);
    if (completionWeight != -1) {
        client->setCompletionWeight(completionWeight);
    }
}

void LdapClientSearch::updateCompletionWeights()
{
    KConfigGroup config(KLDAP::LdapClientSearchConfig::config(), "LDAP");
    for (int i = 0, total = d->mClients.size(); i < total; ++i) {
        d->readWeighForClient(d->mClients[i], config, i);
    }
}

QList<LdapClient *> LdapClientSearch::clients() const
{
    return d->mClients;
}

QString LdapClientSearch::filter() const
{
    return d->mFilter;
}

void LdapClientSearch::setFilter(const QString &filter)
{
    d->mFilter = filter;
}

QStringList LdapClientSearch::attributes() const
{
    return d->mAttributes;
}

void LdapClientSearch::setAttributes(const QStringList &attrs)
{
    if (attrs != d->mAttributes) {
        d->mAttributes = attrs;
        d->readConfig();
    }
}

QStringList LdapClientSearch::defaultAttributes()
{
    const QStringList attr{QStringLiteral("cn"), QStringLiteral("mail"), QStringLiteral("givenname"), QStringLiteral("sn")};
    return attr;
}

void LdapClientSearch::LdapClientSearchPrivate::readConfig()
{
    q->cancelSearch();
    qDeleteAll(mClients);
    mClients.clear();

    // stolen from KAddressBook
    KConfigGroup config(KLDAP::LdapClientSearchConfig::config(), "LDAP");
    const int numHosts = config.readEntry("NumSelectedHosts", 0);
    if (!numHosts) {
        mNoLDAPLookup = true;
    } else {
        for (int j = 0; j < numHosts; ++j) {
            auto ldapClient = new LdapClient(j, q);
            auto job = new LdapSearchClientReadConfigServerJob;
            job->setCurrentIndex(j);
            job->setActive(true);
            job->setConfig(config);
            job->setLdapClient(ldapClient);
            job->start();

            mNoLDAPLookup = false;
            readWeighForClient(ldapClient, config, j);

            ldapClient->setAttributes(mAttributes);

            q->connect(ldapClient, &LdapClient::result, q, [this](const LdapClient &client, const KLDAP::LdapObject &obj) {
                slotLDAPResult(client, obj);
            });
            q->connect(ldapClient, &LdapClient::done, q, [this]() {
                slotLDAPDone();
            });
            q->connect(ldapClient, qOverload<const QString &>(&LdapClient::error), q, [this](const QString &str) {
                slotLDAPError(str);
            });

            mClients.append(ldapClient);
        }

        q->connect(&mDataTimer, &QTimer::timeout, q, [this]() {
            slotDataTimer();
        });
    }
    mConfigFile = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + QStringLiteral("/kabldaprc");
    KDirWatch::self()->addFile(mConfigFile);
}

void LdapClientSearch::LdapClientSearchPrivate::slotFileChanged(const QString &file)
{
    if (file == mConfigFile) {
        readConfig();
    }
}

void LdapClientSearch::startSearch(const QString &txt)
{
    if (d->mNoLDAPLookup) {
        QMetaObject::invokeMethod(this, &LdapClientSearch::searchDone, Qt::QueuedConnection);
        return;
    }

    cancelSearch();

    int pos = txt.indexOf(QLatin1Char('\"'));
    if (pos >= 0) {
        ++pos;
        const int pos2 = txt.indexOf(QLatin1Char('\"'), pos);
        if (pos2 >= 0) {
            d->mSearchText = txt.mid(pos, pos2 - pos);
        } else {
            d->mSearchText = txt.mid(pos);
        }
    } else {
        d->mSearchText = txt;
    }

    const QString filter = d->mFilter.arg(d->mSearchText);

    QList<LdapClient *>::Iterator it(d->mClients.begin());
    const QList<LdapClient *>::Iterator end(d->mClients.end());
    for (; it != end; ++it) {
        (*it)->startQuery(filter);
        qCDebug(LDAPCLIENT_LOG) << "LdapClientSearch::startSearch()" << filter;
        ++d->mActiveClients;
    }
}

void LdapClientSearch::cancelSearch()
{
    QList<LdapClient *>::Iterator it(d->mClients.begin());
    const QList<LdapClient *>::Iterator end(d->mClients.end());
    for (; it != end; ++it) {
        (*it)->cancelQuery();
    }

    d->mActiveClients = 0;
    d->mResults.clear();
}

void LdapClientSearch::LdapClientSearchPrivate::slotLDAPResult(const LdapClient &client, const KLDAP::LdapObject &obj)
{
    LdapResultObject result;
    result.client = &client;
    result.object = obj;

    mResults.append(result);
    if (!mDataTimer.isActive()) {
        mDataTimer.setSingleShot(true);
        mDataTimer.start(500);
    }
}

void LdapClientSearch::LdapClientSearchPrivate::slotLDAPError(const QString &)
{
    slotLDAPDone();
}

void LdapClientSearch::LdapClientSearchPrivate::slotLDAPDone()
{
    if (--mActiveClients > 0) {
        return;
    }

    finish();
}

void LdapClientSearch::LdapClientSearchPrivate::slotDataTimer()
{
    QStringList lst;
    LdapResult::List reslist;

    Q_EMIT q->searchData(mResults);

    makeSearchData(lst, reslist);
    if (!lst.isEmpty()) {
        Q_EMIT q->searchData(lst);
    }
    if (!reslist.isEmpty()) {
        Q_EMIT q->searchData(reslist);
    }
}

void LdapClientSearch::LdapClientSearchPrivate::finish()
{
    mDataTimer.stop();

    slotDataTimer(); // Q_EMIT final bunch of data
    Q_EMIT q->searchDone();
}

void LdapClientSearch::LdapClientSearchPrivate::makeSearchData(QStringList &ret, LdapResult::List &resList)
{
    LdapResultObject::List::ConstIterator it1(mResults.constBegin());
    const LdapResultObject::List::ConstIterator end1(mResults.constEnd());
    for (; it1 != end1; ++it1) {
        QString name;
        QString mail;
        QString givenname;
        QString sn;
        QStringList mails;
        bool isDistributionList = false;
        bool wasCN = false;
        bool wasDC = false;

        // qCDebug(LDAPCLIENT_LOG) <<"\n\nLdapClientSearch::makeSearchData()";

        KLDAP::LdapAttrMap::ConstIterator it2;
        for (it2 = (*it1).object.attributes().constBegin(); it2 != (*it1).object.attributes().constEnd(); ++it2) {
            QByteArray val = (*it2).first();
            int len = val.size();
            if (len > 0 && '\0' == val[len - 1]) {
                --len;
            }
            const QString tmp = QString::fromUtf8(val.constData(), len);
            // qCDebug(LDAPCLIENT_LOG) <<"      key: \"" << it2.key() <<"\" value: \"" << tmp <<"\"";
            if (it2.key() == QLatin1String("cn")) {
                name = tmp;
                if (mail.isEmpty()) {
                    mail = tmp;
                } else {
                    if (wasCN) {
                        mail.prepend(QLatin1Char('.'));
                    } else {
                        mail.prepend(QLatin1Char('@'));
                    }
                    mail.prepend(tmp);
                }
                wasCN = true;
            } else if (it2.key() == QLatin1String("dc")) {
                if (mail.isEmpty()) {
                    mail = tmp;
                } else {
                    if (wasDC) {
                        mail.append(QLatin1Char('.'));
                    } else {
                        mail.append(QLatin1Char('@'));
                    }
                    mail.append(tmp);
                }
                wasDC = true;
            } else if (it2.key() == QLatin1String("mail")) {
                mail = tmp;
                KLDAP::LdapAttrValue::ConstIterator it3 = it2.value().constBegin();
                for (; it3 != it2.value().constEnd(); ++it3) {
                    mails.append(QString::fromUtf8((*it3).data(), (*it3).size()));
                }
            } else if (it2.key() == QLatin1String("givenName")) {
                givenname = tmp;
            } else if (it2.key() == QLatin1String("sn")) {
                sn = tmp;
            } else if (it2.key() == QLatin1String("objectClass") && (tmp == QLatin1String("groupOfNames") || tmp == QLatin1String("kolabGroupOfNames"))) {
                isDistributionList = true;
            }
        }

        if (mails.isEmpty()) {
            if (!mail.isEmpty()) {
                mails.append(mail);
            }
            if (isDistributionList) {
                // qCDebug(LDAPCLIENT_LOG) <<"\n\nLdapClientSearch::makeSearchData() found a list:" << name;
                ret.append(name);
                // following lines commented out for bugfixing kolab issue #177:
                //
                // Unlike we thought previously we may NOT append the server name here.
                //
                // The right server is found by the SMTP server instead: Kolab users
                // must use the correct SMTP server, by definition.
                //
                // mail = (*it1).client->base().simplified();
                // mail.replace( ",dc=", ".", false );
                // if( mail.startsWith("dc=", false) )
                //  mail.remove(0, 3);
                // mail.prepend( '@' );
                // mail.prepend( name );
                // mail = name;
            } else {
                continue; // nothing, bad entry
            }
        } else if (name.isEmpty()) {
            ret.append(mail);
        } else {
            ret.append(QStringLiteral("%1 <%2>").arg(name, mail));
        }

        LdapResult sr;
        sr.dn = (*it1).object.dn();
        sr.clientNumber = (*it1).client->clientNumber();
        sr.completionWeight = (*it1).client->completionWeight();
        sr.name = name;
        sr.email = mails;
        resList.append(sr);
    }

    mResults.clear();
}

bool LdapClientSearch::isAvailable() const
{
    return !d->mNoLDAPLookup;
}

#include "moc_ldapclientsearch.cpp"
