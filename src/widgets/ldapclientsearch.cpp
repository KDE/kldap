/* kldapclient.cpp - LDAP access
 * SPDX-FileCopyrightText: 2002 Klarälvdalens Datakonsult AB
 * SPDX-FileContributor: Steffen Hansen <hansen@kde.org>
 *
 * Ported to KABC by Daniel Molkentin <molkentin@kde.org>
 *
 * SPDX-FileCopyrightText: 2013-2020 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearch.h"
#include "ldapclientsearchconfig.h"
#include "ldapclient_debug.h"

#include "ldapclient.h"

#include <kldap/ldapserver.h>
#include <kldap/ldapurl.h>
#include <kldap/ldif.h>

#include <KConfig>
#include <KConfigGroup>
#include <KDirWatch>
#include <KProtocolInfo>
#include <Kdelibs4ConfigMigrator>

#include <kio/job.h>

#include <QTimer>
#include <QStandardPaths>

using namespace KLDAP;

class Q_DECL_HIDDEN LdapClientSearch::Private
{
public:
    Private(LdapClientSearch *qq)
        : q(qq)
    {
        mClientSearchConfig = new LdapClientSearchConfig;
    }

    ~Private()
    {
        delete mClientSearchConfig;
    }

    void readWeighForClient(LdapClient *client, const KConfigGroup &config, int clientNumber);
    void readConfig();
    void finish();
    void makeSearchData(QStringList &ret, LdapResult::List &resList);

    void slotLDAPResult(const KLDAP::LdapClient &client, const KLDAP::LdapObject &);
    void slotLDAPError(const QString &);
    void slotLDAPDone();
    void slotDataTimer();
    void slotFileChanged(const QString &);

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
    LdapClientSearchConfig *mClientSearchConfig = nullptr;
};

LdapClientSearch::LdapClientSearch(QObject *parent)
    : QObject(parent)
    , d(new Private(this))
{
    Kdelibs4ConfigMigrator migrate(QStringLiteral("ldapsettings"));
    migrate.setConfigFiles(QStringList() << QStringLiteral("kabldaprc"));
    migrate.migrate();

    if (!KProtocolInfo::isKnownProtocol(QUrl(QStringLiteral("ldap://localhost")))) {
        d->mNoLDAPLookup = true;
        return;
    }

    d->mAttributes << QStringLiteral("cn")
                   << QStringLiteral("mail")
                   << QStringLiteral("givenname")
                   << QStringLiteral("sn");

    // Set the filter, to make sure old usage (before 4.14) of this object still works.
    d->mFilter = QStringLiteral("&(|(objectclass=person)(objectclass=groupOfNames)(mail=*))"
                                "(|(cn=%1*)(mail=%1*)(givenName=%1*)(sn=%1*))");

    d->readConfig();
    connect(KDirWatch::self(), &KDirWatch::dirty, this, [this](const QString &filename) {
        d->slotFileChanged(filename);
    });
}

LdapClientSearch::~LdapClientSearch()
{
    delete d;
}

void LdapClientSearch::Private::readWeighForClient(LdapClient *client, const KConfigGroup &config, int clientNumber)
{
    const int completionWeight = config.readEntry(QStringLiteral("SelectedCompletionWeight%1").arg(clientNumber), -1);
    if (completionWeight != -1) {
        client->setCompletionWeight(completionWeight);
    }
}

void LdapClientSearch::updateCompletionWeights()
{
    KConfigGroup config(KLDAP::LdapClientSearchConfig::config(), "LDAP");
    for (int i = 0; i < d->mClients.size(); ++i) {
        d->readWeighForClient(d->mClients[ i ], config, i);
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

void LdapClientSearch::Private::readConfig()
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
            auto *ldapClient = new LdapClient(j, q);
            KLDAP::LdapServer server;
            mClientSearchConfig->readConfig(server, config, j, true);
            if (!server.host().isEmpty()) {
                mNoLDAPLookup = false;
            }
            ldapClient->setServer(server);

            readWeighForClient(ldapClient, config, j);

            ldapClient->setAttributes(mAttributes);

            q->connect(ldapClient, &LdapClient::result,
                       q, [this](const LdapClient &client, const KLDAP::LdapObject &obj) {
                slotLDAPResult(client, obj);
            });
            q->connect(ldapClient, &LdapClient::done,
                       q, [this]() {
                slotLDAPDone();
            });
            q->connect(ldapClient, qOverload<const QString &>(&LdapClient::error),
                       q, [this](const QString &str) {
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

void LdapClientSearch::Private::slotFileChanged(const QString &file)
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

void LdapClientSearch::Private::slotLDAPResult(const LdapClient &client, const KLDAP::LdapObject &obj)
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

void LdapClientSearch::Private::slotLDAPError(const QString &)
{
    slotLDAPDone();
}

void LdapClientSearch::Private::slotLDAPDone()
{
    if (--mActiveClients > 0) {
        return;
    }

    finish();
}

void LdapClientSearch::Private::slotDataTimer()
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

void LdapClientSearch::Private::finish()
{
    mDataTimer.stop();

    slotDataTimer(); // Q_EMIT final bunch of data
    Q_EMIT q->searchDone();
}

void LdapClientSearch::Private::makeSearchData(QStringList &ret, LdapResult::List &resList)
{
    LdapResultObject::List::ConstIterator it1(mResults.constBegin());
    const LdapResultObject::List::ConstIterator end1(mResults.constEnd());
    for (; it1 != end1; ++it1) {
        QString name, mail, givenname, sn;
        QStringList mails;
        bool isDistributionList = false;
        bool wasCN = false;
        bool wasDC = false;

        //qCDebug(LDAPCLIENT_LOG) <<"\n\nLdapClientSearch::makeSearchData()";

        KLDAP::LdapAttrMap::ConstIterator it2;
        for (it2 = (*it1).object.attributes().constBegin();
             it2 != (*it1).object.attributes().constEnd(); ++it2) {
            QByteArray val = (*it2).first();
            int len = val.size();
            if (len > 0 && '\0' == val[len - 1]) {
                --len;
            }
            const QString tmp = QString::fromUtf8(val.constData(), len);
            //qCDebug(LDAPCLIENT_LOG) <<"      key: \"" << it2.key() <<"\" value: \"" << tmp <<"\"";
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
            } else if (it2.key() == QLatin1String("objectClass")
                       && (tmp == QLatin1String("groupOfNames") || tmp == QLatin1String("kolabGroupOfNames"))) {
                isDistributionList = true;
            }
        }

        if (mails.isEmpty()) {
            if (!mail.isEmpty()) {
                mails.append(mail);
            }
            if (isDistributionList) {
                //qCDebug(LDAPCLIENT_LOG) <<"\n\nLdapClientSearch::makeSearchData() found a list:" << name;
                ret.append(name);
                // following lines commented out for bugfixing kolab issue #177:
                //
                // Unlike we thought previously we may NOT append the server name here.
                //
                // The right server is found by the SMTP server instead: Kolab users
                // must use the correct SMTP server, by definition.
                //
                //mail = (*it1).client->base().simplified();
                //mail.replace( ",dc=", ".", false );
                //if( mail.startsWith("dc=", false) )
                //  mail.remove(0, 3);
                //mail.prepend( '@' );
                //mail.prepend( name );
                //mail = name;
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
