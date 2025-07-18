/* kldapclient.cpp - LDAP access
 * SPDX-FileCopyrightText: 2002 Klarälvdalens Datakonsult AB
 * SPDX-FileContributor: Steffen Hansen <hansen@kde.org>
 *
 * Ported to KABC by Daniel Molkentin <molkentin@kde.org>
 *
 * SPDX-FileCopyrightText: 2013-2025 Laurent Montel <montel@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclientsearch.h"
#include "kldapcore/ldapclientsearchconfig.h"
#include "ldapclient_core_debug.h"
#include "ldapsearchclientreadconfigserverjob.h"

#include "ldapclient.h"

#include "kldapcore/ldapserver.h"
#include "kldapcore/ldapurl.h"
#include "kldapcore/ldif.h"

#include <KConfig>
#include <KConfigGroup>
#include <KDirWatch>
#include <KProtocolInfo>

#include <KIO/Job>

#include <QStandardPaths>
#include <QTimer>

using namespace KLDAPCore;
using namespace Qt::Literals::StringLiterals;

class Q_DECL_HIDDEN LdapClientSearch::LdapClientSearchPrivate
{
public:
    LdapClientSearchPrivate(LdapClientSearch *qq)
        : q(qq)
    {
    }

    ~LdapClientSearchPrivate() = default;

    void readWeighForClient(KLDAPCore::LdapClient *client, const KConfigGroup &config, int clientNumber);
    void readConfig();
    void finish();
    void makeSearchData(QStringList &ret, LdapResult::List &resList);

    void slotLDAPResult(const KLDAPCore::LdapClient &client, const KLDAPCore::LdapObject &);
    void slotLDAPError(const QString &);
    void slotLDAPDone();
    void slotDataTimer();
    void slotFileChanged(const QString &);
    void init(const QStringList &attributes);

    LdapClientSearch *const q;
    QList<KLDAPCore::LdapClient *> mClients;
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
    if (!KProtocolInfo::isKnownProtocol(QUrl(u"ldap://localhost"_s))) {
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

void LdapClientSearch::LdapClientSearchPrivate::readWeighForClient(KLDAPCore::LdapClient *client, const KConfigGroup &config, int clientNumber)
{
    const int completionWeight = config.readEntry(u"SelectedCompletionWeight%1"_s.arg(clientNumber), -1);
    if (completionWeight != -1) {
        client->setCompletionWeight(completionWeight);
    }
}

void LdapClientSearch::updateCompletionWeights()
{
    KConfigGroup config(KLDAPCore::LdapClientSearchConfig::config(), u"LDAP"_s);
    for (int i = 0, total = d->mClients.size(); i < total; ++i) {
        d->readWeighForClient(d->mClients[i], config, i);
    }
}

QList<KLDAPCore::LdapClient *> LdapClientSearch::clients() const
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
    const QStringList attr{u"cn"_s, u"mail"_s, QStringLiteral("givenname"), QStringLiteral("sn")};
    return attr;
}

void LdapClientSearch::LdapClientSearchPrivate::readConfig()
{
    q->cancelSearch();
    qDeleteAll(mClients);
    mClients.clear();

    // stolen from KAddressBook
    KConfigGroup config(KLDAPCore::LdapClientSearchConfig::config(), u"LDAP"_s);
    const int numHosts = config.readEntry("NumSelectedHosts", 0);
    if (!numHosts) {
        mNoLDAPLookup = true;
    } else {
        for (int j = 0; j < numHosts; ++j) {
            auto ldapClient = new KLDAPCore::LdapClient(j, q);
            auto job = new KLDAPCore::LdapSearchClientReadConfigServerJob;
            job->setCurrentIndex(j);
            job->setActive(true);
            job->setConfig(config);
            job->setLdapClient(ldapClient);
            job->start();

            mNoLDAPLookup = false;
            readWeighForClient(ldapClient, config, j);

            ldapClient->setAttributes(mAttributes);

            q->connect(ldapClient, &KLDAPCore::LdapClient::result, q, [this](const KLDAPCore::LdapClient &client, const KLDAPCore::LdapObject &obj) {
                slotLDAPResult(client, obj);
            });
            q->connect(ldapClient, &KLDAPCore::LdapClient::done, q, [this]() {
                slotLDAPDone();
            });
            q->connect(ldapClient, qOverload<const QString &>(&KLDAPCore::LdapClient::error), q, [this](const QString &str) {
                slotLDAPError(str);
            });

            mClients.append(ldapClient);
        }

        q->connect(&mDataTimer, &QTimer::timeout, q, [this]() {
            slotDataTimer();
        });
    }
    mConfigFile = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + u"/kabldaprc"_s;
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

    int pos = txt.indexOf(u'\"');
    if (pos >= 0) {
        ++pos;
        const int pos2 = txt.indexOf(u'\"', pos);
        if (pos2 >= 0) {
            d->mSearchText = txt.mid(pos, pos2 - pos);
        } else {
            d->mSearchText = txt.mid(pos);
        }
    } else {
        d->mSearchText = txt;
    }

    const QString filter = d->mFilter.arg(d->mSearchText);

    QList<KLDAPCore::LdapClient *>::Iterator it(d->mClients.begin());
    const QList<KLDAPCore::LdapClient *>::Iterator end(d->mClients.end());
    for (; it != end; ++it) {
        (*it)->startQuery(filter);
        qCDebug(LDAPCLIENT_CORE_LOG) << "LdapClientSearch::startSearch()" << filter;
        ++d->mActiveClients;
    }
}

void LdapClientSearch::cancelSearch()
{
    QList<KLDAPCore::LdapClient *>::Iterator it(d->mClients.begin());
    const QList<KLDAPCore::LdapClient *>::Iterator end(d->mClients.end());
    for (; it != end; ++it) {
        (*it)->cancelQuery();
    }

    d->mActiveClients = 0;
    d->mResults.clear();
}

void LdapClientSearch::LdapClientSearchPrivate::slotLDAPResult(const KLDAPCore::LdapClient &client, const KLDAPCore::LdapObject &obj)
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

void LdapClientSearch::LdapClientSearchPrivate::makeSearchData(QStringList &ret, KLDAPCore::LdapResult::List &resList)
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

        KLDAPCore::LdapAttrMap::ConstIterator it2;
        for (it2 = (*it1).object.attributes().constBegin(); it2 != (*it1).object.attributes().constEnd(); ++it2) {
            QByteArray val = (*it2).first();
            int len = val.size();
            if (len > 0 && '\0' == val[len - 1]) {
                --len;
            }
            const QString tmp = QString::fromUtf8(val.constData(), len);
            // qCDebug(LDAPCLIENT_LOG) <<"      key: \"" << it2.key() <<"\" value: \"" << tmp <<"\"";
            if (it2.key() == "cn"_L1) {
                name = tmp;
                if (mail.isEmpty()) {
                    mail = tmp;
                } else {
                    if (wasCN) {
                        mail.prepend(u'.');
                    } else {
                        mail.prepend(u'@');
                    }
                    mail.prepend(tmp);
                }
                wasCN = true;
            } else if (it2.key() == "dc"_L1) {
                if (mail.isEmpty()) {
                    mail = tmp;
                } else {
                    if (wasDC) {
                        mail.append(u'.');
                    } else {
                        mail.append(u'@');
                    }
                    mail.append(tmp);
                }
                wasDC = true;
            } else if (it2.key() == "mail"_L1) {
                mail = tmp;
                KLDAPCore::LdapAttrValue::ConstIterator it3 = it2.value().constBegin();
                for (; it3 != it2.value().constEnd(); ++it3) {
                    mails.append(QString::fromUtf8((*it3).data(), (*it3).size()));
                }
            } else if (it2.key() == "givenName"_L1) {
                givenname = tmp;
            } else if (it2.key() == "sn"_L1) {
                sn = tmp;
            } else if (it2.key() == "objectClass"_L1 && (tmp == "groupOfNames"_L1 || tmp == "kolabGroupOfNames"_L1)) {
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
            ret.append(u"%1 <%2>"_s.arg(name, mail));
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
