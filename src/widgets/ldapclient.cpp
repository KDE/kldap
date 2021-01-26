/* kldapclient.cpp - LDAP access
 * SPDX-FileCopyrightText: 2002 Klarälvdalens Datakonsult AB
 * SPDX-FileContributor: Steffen Hansen <hansen@kde.org>
 *
 * Ported to KABC by Daniel Molkentin <molkentin@kde.org>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "ldapclient.h"
#include "ldapclient_debug.h"

#include <kldap/ldapobject.h>
#include <kldap/ldapserver.h>
#include <kldap/ldapurl.h>
#include <kldap/ldif.h>

#include <kio/job.h>

#include <QPointer>

using namespace KLDAP;

class Q_DECL_HIDDEN LdapClient::Private
{
public:
    Private(LdapClient *qq)
        : q(qq)
    {
    }

    ~Private()
    {
        q->cancelQuery();
    }

    void startParseLDIF();
    void parseLDIF(const QByteArray &data);
    void endParseLDIF();
    void finishCurrentObject();

    void slotData(KIO::Job *, const QByteArray &data);
    void slotInfoMessage(KJob *, const QString &info, const QString &);
    void slotDone();

    LdapClient *const q;

    KLDAP::LdapServer mServer;
    QString mScope;
    QStringList mAttrs;

    QPointer<KJob> mJob = nullptr;
    bool mActive = false;

    KLDAP::LdapObject mCurrentObject;
    KLDAP::Ldif mLdif;
    int mClientNumber = 0;
    int mCompletionWeight = 0;
};

LdapClient::LdapClient(int clientNumber, QObject *parent)
    : QObject(parent)
    , d(new Private(this))
{
    d->mClientNumber = clientNumber;
    d->mCompletionWeight = 50 - d->mClientNumber;
}

LdapClient::~LdapClient()
{
    delete d;
}

bool LdapClient::isActive() const
{
    return d->mActive;
}

void LdapClient::setServer(const KLDAP::LdapServer &server)
{
    d->mServer = server;
}

const KLDAP::LdapServer LdapClient::server() const
{
    return d->mServer;
}

void LdapClient::setAttributes(const QStringList &attrs)
{
    d->mAttrs = attrs;
    d->mAttrs << QStringLiteral("objectClass"); // via objectClass we detect distribution lists
}

QStringList LdapClient::attributes() const
{
    return d->mAttrs;
}

void LdapClient::setScope(const QString &scope)
{
    d->mScope = scope;
}

void LdapClient::startQuery(const QString &filter)
{
    cancelQuery();
    KLDAP::LdapUrl url{d->mServer.url()};

    url.setAttributes(d->mAttrs);
    url.setScope(d->mScope == QLatin1String("one") ? KLDAP::LdapUrl::One : KLDAP::LdapUrl::Sub);
    const QString userFilter = url.filter();
    QString finalFilter = filter;
    // combine the filter set by the user in the config dialog (url.filter()) and the filter from this query
    if (!userFilter.isEmpty()) {
        finalFilter = QLatin1String("&(") + finalFilter + QLatin1String(")(") + userFilter + QLatin1Char(')');
    }
    url.setFilter(QLatin1Char('(') + finalFilter + QLatin1Char(')'));

    qCDebug(LDAPCLIENT_LOG) << "LdapClient: Doing query:" << url.toDisplayString();

    d->startParseLDIF();
    d->mActive = true;
    KIO::TransferJob *transfertJob = KIO::get(url, KIO::NoReload, KIO::HideProgressInfo);
    d->mJob = transfertJob;
    connect(transfertJob, &KIO::TransferJob::data, this, [this](KIO::Job *job, const QByteArray &data) {
        d->slotData(job, data);
    });
    connect(d->mJob.data(), &KIO::TransferJob::infoMessage, this, [this](KJob *job, const QString &str, const QString &val) {
        d->slotInfoMessage(job, str, val);
    });
    connect(d->mJob.data(), &KIO::TransferJob::result, this, [this]() {
        d->slotDone();
    });
}

void LdapClient::cancelQuery()
{
    if (d->mJob) {
        d->mJob->kill();
        d->mJob = nullptr;
    }

    d->mActive = false;
}

void LdapClient::Private::slotData(KIO::Job *, const QByteArray &data)
{
    parseLDIF(data);
}

void LdapClient::Private::slotInfoMessage(KJob *, const QString &info, const QString &)
{
    qCDebug(LDAPCLIENT_LOG) << "Job said :" << info;
}

void LdapClient::Private::slotDone()
{
    endParseLDIF();
    mActive = false;
    if (!mJob) {
        return;
    }
    int err = mJob->error();
    if (err && err != KIO::ERR_USER_CANCELED) {
        Q_EMIT q->error(mJob->errorString());
    }
    Q_EMIT q->done();
}

void LdapClient::Private::startParseLDIF()
{
    mCurrentObject.clear();
    mLdif.startParsing();
}

void LdapClient::Private::endParseLDIF()
{
}

void LdapClient::Private::finishCurrentObject()
{
    mCurrentObject.setDn(mLdif.dn());
    KLDAP::LdapAttrValue objectclasses;
    const KLDAP::LdapAttrMap::ConstIterator end = mCurrentObject.attributes().constEnd();
    for (KLDAP::LdapAttrMap::ConstIterator it = mCurrentObject.attributes().constBegin(); it != end; ++it) {
        if (it.key().toLower() == QLatin1String("objectclass")) {
            objectclasses = it.value();
            break;
        }
    }

    bool groupofnames = false;
    const KLDAP::LdapAttrValue::ConstIterator endValue(objectclasses.constEnd());
    for (KLDAP::LdapAttrValue::ConstIterator it = objectclasses.constBegin(); it != endValue; ++it) {
        const QByteArray sClass = (*it).toLower();
        if (sClass == "groupofnames" || sClass == "kolabgroupofnames") {
            groupofnames = true;
        }
    }

    if (groupofnames) {
        KLDAP::LdapAttrMap::ConstIterator it = mCurrentObject.attributes().find(QStringLiteral("mail"));
        if (it == mCurrentObject.attributes().end()) {
            // No explicit mail address found so far?
            // Fine, then we use the address stored in the DN.
            QString sMail;
            const QStringList lMail = mCurrentObject.dn().toString().split(QStringLiteral(",dc="), Qt::SkipEmptyParts);
            const int n = lMail.count();
            if (n) {
                if (lMail.first().startsWith(QLatin1String("cn="), Qt::CaseInsensitive)) {
                    sMail = lMail.first().simplified().mid(3);
                    if (1 < n) {
                        sMail.append(QLatin1Char('@'));
                    }
                    for (int i = 1; i < n; ++i) {
                        sMail.append(lMail.at(i));
                        if (i < n - 1) {
                            sMail.append(QLatin1Char('.'));
                        }
                    }
                    mCurrentObject.addValue(QStringLiteral("mail"), sMail.toUtf8());
                }
            }
        }
    }
    Q_EMIT q->result(*q, mCurrentObject);
    mCurrentObject.clear();
}

void LdapClient::Private::parseLDIF(const QByteArray &data)
{
    // qCDebug(LDAPCLIENT_LOG) <<"LdapClient::parseLDIF(" << QCString(data.data(), data.size()+1) <<" )";
    if (!data.isEmpty()) {
        mLdif.setLdif(data);
    } else {
        mLdif.endLdif();
    }
    KLDAP::Ldif::ParseValue ret;
    QString name;
    do {
        ret = mLdif.nextItem();
        switch (ret) {
        case KLDAP::Ldif::Item: {
            name = mLdif.attr();
            const QByteArray value = mLdif.value();
            mCurrentObject.addValue(name, value);
            break;
        }
        case KLDAP::Ldif::EndEntry:
            finishCurrentObject();
            break;
        default:
            break;
        }
    } while (ret != KLDAP::Ldif::MoreData);
}

int LdapClient::clientNumber() const
{
    return d->mClientNumber;
}

int LdapClient::completionWeight() const
{
    return d->mCompletionWeight;
}

void LdapClient::setCompletionWeight(int weight)
{
    d->mCompletionWeight = weight;
}

#include "moc_ldapclient.cpp"
