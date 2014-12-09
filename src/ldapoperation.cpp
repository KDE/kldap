/*
  This file is part of libkldap.
  Copyright (c) 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General  Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; see the file COPYING.LIB.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#include "ldapoperation.h"
#include "kldap_config.h"

#include <qdebug.h>

#include <QtCore/QTime>

#include <stdlib.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef SASL2_FOUND
#include <sasl/sasl.h>
#endif

#ifdef LDAP_FOUND
# ifndef HAVE_WINLDAP_H
#  include <lber.h>
#  include <ldap.h>
# else
#  include <w32-ldap-help.h>
# endif // HAVE_WINLDAP_H
#endif // LDAP_FOUND

#include "ldapdefs.h"

using namespace KLDAP;

#ifdef LDAP_FOUND
static void extractControls(LdapControls &ctrls, LDAPControl **pctrls);
#endif // LDAP_FOUND

/*
   Returns the difference between msecs and elapsed. If msecs is -1,
   however, -1 is returned.
*/
static int kldap_timeout_value(int msecs, int elapsed)
{
    if (msecs == -1) {
        return -1;
    }

    int timeout = msecs - elapsed;
    return timeout < 0 ? 0 : timeout;
}

class LdapOperation::LdapOperationPrivate
{
public:
    LdapOperationPrivate();
    ~LdapOperationPrivate();
#ifdef LDAP_FOUND
    int processResult(int rescode, LDAPMessage *msg);
    int bind(const QByteArray &creds, SASL_Callback_Proc *saslproc, void *data, bool async);
#endif
    LdapControls mClientCtrls, mServerCtrls, mControls;
    LdapObject mObject;
    QByteArray mExtOid, mExtData;
    QByteArray mServerCred;
    QString mMatchedDn;
    QList<QByteArray> mReferrals;

    LdapConnection *mConnection;
};

LdapOperation::LdapOperation()
    : d(new LdapOperationPrivate)
{
    d->mConnection = 0;
}

LdapOperation::LdapOperation(LdapConnection &conn)
    : d(new LdapOperationPrivate)
{
    setConnection(conn);
}

LdapOperation::~LdapOperation()
{
    delete d;
}

void LdapOperation::setConnection(LdapConnection &conn)
{
    d->mConnection = &conn;
}

LdapConnection &LdapOperation::connection()
{
    return *d->mConnection;
}

void LdapOperation::setClientControls(const LdapControls &ctrls)
{
    d->mClientCtrls = ctrls;
}

void LdapOperation::setServerControls(const LdapControls &ctrls)
{
    d->mServerCtrls = ctrls;
}

LdapControls LdapOperation::clientControls() const
{
    return d->mClientCtrls;
}

LdapControls LdapOperation::serverControls() const
{
    return d->mServerCtrls;
}

LdapObject LdapOperation::object() const
{
    return d->mObject;
}

LdapControls LdapOperation::controls() const
{
    return d->mControls;
}

QByteArray LdapOperation::extendedOid() const
{
    return d->mExtOid;
}

QByteArray LdapOperation::extendedData() const
{
    return d->mExtData;
}

QString LdapOperation::matchedDn() const
{
    return d->mMatchedDn;
}

QList<QByteArray> LdapOperation::referrals() const
{
    return d->mReferrals;
}

QByteArray LdapOperation::serverCred() const
{
    return d->mServerCred;
}

LdapOperation::LdapOperationPrivate::LdapOperationPrivate()
{
}

LdapOperation::LdapOperationPrivate::~LdapOperationPrivate()
{
}

#ifdef LDAP_FOUND

#ifdef SASL2_FOUND
static int kldap_sasl_interact(sasl_interact_t *interact, LdapOperation::SASL_Data *data)
{
    if (data->proc) {
        for (; interact->id != SASL_CB_LIST_END; interact++) {
            switch (interact->id) {
            case SASL_CB_GETREALM:
                data->creds.fields |= LdapOperation::SASL_Realm;
                break;
            case SASL_CB_AUTHNAME:
                data->creds.fields |= LdapOperation::SASL_Authname;
                break;
            case SASL_CB_PASS:
                data->creds.fields |= LdapOperation::SASL_Password;
                break;
            case SASL_CB_USER:
                data->creds.fields |= LdapOperation::SASL_Authzid;
                break;
            }
        }
        int retval;
        if ((retval = data->proc(data->creds, data->data))) {
            return retval;
        }
    }

    QString value;

    while (interact->id != SASL_CB_LIST_END) {
        value.clear();
        switch (interact->id) {
        case SASL_CB_GETREALM:
            value = data->creds.realm;
            qDebug() << "SASL_REALM=" << value;
            break;
        case SASL_CB_AUTHNAME:
            value = data->creds.authname;
            qDebug() << "SASL_AUTHNAME=" << value;
            break;
        case SASL_CB_PASS:
            value = data->creds.password;
            qDebug() << "SASL_PASSWD=[hidden]";
            break;
        case SASL_CB_USER:
            value = data->creds.authzid;
            qDebug() << "SASL_AUTHZID=" << value;
            break;
        }
        if (value.isEmpty()) {
            interact->result = NULL;
            interact->len = 0;
        } else {
            interact->result = strdup(value.toUtf8());
            interact->len = strlen((const char *)interact->result);
        }
        interact++;
    }
    return KLDAP_SUCCESS;
}
#endif

int LdapOperation::LdapOperationPrivate::bind(const QByteArray &creds,
        SASL_Callback_Proc *saslproc,
        void *data, bool async)
{
    Q_ASSERT(mConnection);
    LDAP *ld = (LDAP *) mConnection->handle();
    LdapServer server;
    server = mConnection->server();

    int ret;

    if (server.auth() == LdapServer::SASL) {
#if defined( SASL2_FOUND ) && !defined( HAVE_WINLDAP_H )
        sasl_conn_t *saslconn = (sasl_conn_t *)mConnection->saslHandle();
        sasl_interact_t *client_interact = NULL;
        const char *out = NULL;
        uint outlen;
        const char *mechusing = NULL;
        struct berval ccred, *scred;
        int saslresult;
        QByteArray sdata = creds;

        QString mech = server.mech();
        if (mech.isEmpty()) {
            mech = QStringLiteral("DIGEST-MD5");
        }

        SASL_Data sasldata;
        sasldata.proc = saslproc;
        sasldata.data = data;
        sasldata.creds.fields = 0;
        sasldata.creds.realm = server.realm();
        sasldata.creds.authname = server.user();
        sasldata.creds.authzid = server.bindDn();
        sasldata.creds.password = server.password();

        do {
            if (sdata.isEmpty()) {
                do {
                    saslresult = sasl_client_start(saslconn, mech.toLatin1(),
                                                   &client_interact, &out, &outlen, &mechusing);

                    if (saslresult == SASL_INTERACT) {
                        if (kldap_sasl_interact(client_interact, &sasldata) != KLDAP_SUCCESS) {
                            return KLDAP_SASL_ERROR;
                        }
                    }
                    qDebug() << "sasl_client_start mech: "
                             << mechusing << " outlen " << outlen
                             << " result: " << saslresult;
                } while (saslresult == SASL_INTERACT);
                if (saslresult != SASL_CONTINUE && saslresult != SASL_OK) {
                    return KLDAP_SASL_ERROR;
                }

            } else {
                qDebug() << "sasl_client_step";
                do {
                    saslresult = sasl_client_step(saslconn, sdata.data(), sdata.size(),
                                                  &client_interact, &out, &outlen);
                    if (saslresult == SASL_INTERACT) {
                        if (kldap_sasl_interact(client_interact, &sasldata) != KLDAP_SUCCESS) {
                            return KLDAP_SASL_ERROR;
                        }
                    }
                } while (saslresult == SASL_INTERACT);
                qDebug() << "sasl_client_step result" << saslresult;
                if (saslresult != SASL_CONTINUE && saslresult != SASL_OK) {
                    return KLDAP_SASL_ERROR;
                }
            }

            ccred.bv_val = (char *) out;
            ccred.bv_len = outlen;

            if (async) {
                qDebug() << "ldap_sasl_bind";
                int msgid;
                ret =
                    ldap_sasl_bind(ld, server.bindDn().toUtf8().data(), mech.toLatin1(),
                                   &ccred, 0, 0, &msgid);
                if (ret == 0) {
                    ret = msgid;
                }
                qDebug() << "ldap_sasl_bind msgid" << ret;
            } else {
                qDebug() << "ldap_sasl_bind_s";
                ret =
                    ldap_sasl_bind_s(ld, server.bindDn().toUtf8().data(), mech.toLatin1(),
                                     &ccred, 0, 0, &scred);
                qDebug() << "ldap_sasl_bind_s ret" << ret;
                if (scred) {
                    sdata = QByteArray(scred->bv_val, scred->bv_len);
                } else {
                    sdata = QByteArray();
                }
            }
        } while (!async && ret == KLDAP_SASL_BIND_IN_PROGRESS);
#else
        qCritical() << "SASL authentication is not available "
                    << "(re-compile kldap with cyrus-sasl and OpenLDAP development).";
        return KLDAP_SASL_ERROR;
#endif
    } else { //simple auth
        QByteArray bindname, pass;
        struct berval ccred;
        if (server.auth() == LdapServer::Simple) {
            bindname = server.bindDn().toUtf8();
            pass = server.password().toUtf8();
        }
        ccred.bv_val = pass.data();
        ccred.bv_len = pass.size();
        qDebug() << "binding to server, bindname: " << bindname << " password: *****";

        if (async) {
            qDebug() << "ldap_sasl_bind (simple)";
#ifndef HAVE_WINLDAP_H
            int msgid = 0;
            ret = ldap_sasl_bind(ld, bindname.data(), 0, &ccred, 0, 0, &msgid);
            if (ret == 0) {
                ret = msgid;
            }
#else
            ret = ldap_simple_bind(ld, bindname.data(), pass.data());
#endif
        } else {
            qDebug() << "ldap_sasl_bind_s (simple)";
#ifndef HAVE_WINLDAP_H
            ret = ldap_sasl_bind_s(ld, bindname.data(), 0, &ccred, 0, 0, 0);
#else
            ret = ldap_simple_bind_s(ld, bindname.data(), pass.data());
#endif
        }
    }
    return ret;
}

int LdapOperation::LdapOperationPrivate::processResult(int rescode, LDAPMessage *msg)
{
    //qDebug();
    int retval;
    LDAP *ld = (LDAP *) mConnection->handle();

    qDebug() << "rescode: " << rescode;
    switch (rescode) {
    case RES_SEARCH_ENTRY: {
        //qDebug() << "Found search entry";
        mObject.clear();
        LdapAttrMap attrs;
        char *name;
        struct berval **bvals;
        BerElement     *entry;

        char *dn = ldap_get_dn(ld, msg);
        mObject.setDn(QString::fromUtf8(dn));
        ldap_memfree(dn);

        // iterate over the attributes
        name = ldap_first_attribute(ld, msg, &entry);
        while (name != 0) {
            // print the values
            bvals = ldap_get_values_len(ld, msg, name);
            LdapAttrValue values;
            if (bvals) {
                for (int i = 0; bvals[i] != 0; i++) {
                    char *val = bvals[i]->bv_val;
                    unsigned long len = bvals[i]->bv_len;
                    values.append(QByteArray(val, len));
                }
                ldap_value_free_len(bvals);
            }
            attrs[ QString::fromLatin1(name) ] = values;
            ldap_memfree(name);

            // next attribute
            name = ldap_next_attribute(ld, msg, entry);
        }
        ber_free(entry, 0);
        mObject.setAttributes(attrs);
        break;
    }
    case RES_SEARCH_REFERENCE:
        // Will only get this if following references is disabled. ignore it
        rescode = 0;
        break;
    case RES_EXTENDED: {
        char *retoid;
        struct berval *retdata;
        retval = ldap_parse_extended_result(ld, msg, &retoid, &retdata, 0);
        if (retval != KLDAP_SUCCESS) {
            ldap_msgfree(msg);
            return -1;
        }
        mExtOid = retoid ? QByteArray(retoid) : QByteArray();
        mExtData = retdata ? QByteArray(retdata->bv_val, retdata->bv_len) : QByteArray();
        ldap_memfree(retoid);
        ber_bvfree(retdata);
        break;
    }
    case RES_BIND: {
        struct berval *servercred = 0;
#ifndef HAVE_WINLDAP_H
        // FIXME: Error handling Winldap does not have ldap_parse_sasl_bind_result
        retval = ldap_parse_sasl_bind_result(ld, msg, &servercred, 0);
#else
        retval = KLDAP_SUCCESS;
#endif
        if (retval != KLDAP_SUCCESS && retval != KLDAP_SASL_BIND_IN_PROGRESS) {
            qDebug() << "RES_BIND error: " << retval;
            ldap_msgfree(msg);
            return -1;
        }
        qDebug() << "RES_BIND rescode" << rescode << "retval:" << retval;
        if (servercred) {
            mServerCred = QByteArray(servercred->bv_val, servercred->bv_len);
            ber_bvfree(servercred);
        } else {
            mServerCred = QByteArray();
        }
        break;
    }
    default: {
        LDAPControl **serverctrls = 0;
        char *matcheddn = 0, *errmsg = 0;
        char **referralsp;
        int errcodep;
        retval =
            ldap_parse_result(ld, msg, &errcodep, &matcheddn, &errmsg, &referralsp,
                              &serverctrls, 0);
        qDebug() << "rescode" << rescode << "retval:" << retval
                 << "matcheddn:" << matcheddn << "errcode:"
                 << errcodep << "errmsg:" << errmsg;
        if (retval != KLDAP_SUCCESS) {
            ldap_msgfree(msg);
            return -1;
        }
        mControls.clear();
        if (serverctrls) {
            extractControls(mControls, serverctrls);
            ldap_controls_free(serverctrls);
        }
        mReferrals.clear();
        if (referralsp) {
            char **tmp = referralsp;
            while (*tmp) {
                mReferrals.append(QByteArray(*tmp));
                ldap_memfree(*tmp);
                tmp++;
            }
            ldap_memfree((char *) referralsp);
        }
        mMatchedDn.clear();
        if (matcheddn) {
            mMatchedDn = QString::fromUtf8(matcheddn);
            ldap_memfree(matcheddn);
        }
        if (errmsg) {
            ldap_memfree(errmsg);
        }
    }
    }

    ldap_msgfree(msg);

    return rescode;
}

static void addModOp(LDAPMod ***pmods, int mod_type, const QString &attr,
                     const QByteArray *value = 0)
{
    //  qDebug() << "type:" << mod_type << "attr:" << attr <<
    //    "value:" << QString::fromUtf8(value,value.size()) <<
    //    "size:" << value.size();
    LDAPMod **mods;

    mods = *pmods;

    uint i = 0;

    if (mods == 0) {
        mods = (LDAPMod **)malloc(2 * sizeof(LDAPMod *));
        mods[ 0 ] = (LDAPMod *)malloc(sizeof(LDAPMod));
        mods[ 1 ] = 0;
        memset(mods[ 0 ], 0, sizeof(LDAPMod));
    } else {
        while (mods[ i ] != 0 &&
                (strcmp(attr.toUtf8(), mods[i]->mod_type) != 0 ||
                 (mods[ i ]->mod_op & ~LDAP_MOD_BVALUES) != mod_type)) {
            i++;
        }

        if (mods[ i ] == 0) {
            mods = (LDAPMod **)realloc(mods, (i + 2) * sizeof(LDAPMod *));
            if (mods == 0) {
                qCritical() << "addModOp: realloc";
                return;
            }
            mods[ i + 1 ] = 0;
            mods[ i ] = (LDAPMod *) malloc(sizeof(LDAPMod));
            memset(mods[ i ], 0, sizeof(LDAPMod));
        }
    }

    mods[ i ]->mod_op = mod_type | LDAP_MOD_BVALUES;
    if (mods[ i ]->mod_type == 0) {
        mods[ i ]->mod_type = strdup(attr.toUtf8());
    }

    *pmods = mods;

    if (value == 0) {
        return;
    }

    int vallen = value->size();
    BerValue *berval;
    berval = (BerValue *) malloc(sizeof(BerValue));
    berval -> bv_len = vallen;
    if (vallen > 0) {
        berval -> bv_val = (char *) malloc(vallen);
        memcpy(berval -> bv_val, value->data(), vallen);
    } else {
        berval -> bv_val = 0;
    }

    if (mods[ i ] -> mod_vals.modv_bvals == 0) {
        mods[ i ]->mod_vals.modv_bvals =
            (BerValue **) malloc(sizeof(BerValue *) * 2);
        mods[ i ]->mod_vals.modv_bvals[ 0 ] = berval;
        mods[ i ]->mod_vals.modv_bvals[ 1 ] = 0;
//    qDebug() << "new bervalue struct" << attr << value;
    } else {
        uint j = 0;
        while (mods[ i ]->mod_vals.modv_bvals[ j ] != 0) {
            j++;
        }
        mods[ i ]->mod_vals.modv_bvals =
            (BerValue **)realloc(mods[ i ]->mod_vals.modv_bvals,
                                 (j + 2) * sizeof(BerValue *));
        if (mods[ i ]->mod_vals.modv_bvals == 0) {
            qCritical() << "addModOp: realloc";
            free(berval);
            return;
        }
        mods[ i ]->mod_vals.modv_bvals[ j ] = berval;
        mods[ i ]->mod_vals.modv_bvals[ j + 1 ] = 0;
        qDebug() << j << ". new bervalue";
    }
}

static void addControlOp(LDAPControl ***pctrls, const QString &oid,
                         const QByteArray &value, bool critical)
{
    LDAPControl **ctrls;
    LDAPControl *ctrl = (LDAPControl *) malloc(sizeof(LDAPControl));

    ctrls = *pctrls;

    qDebug() << "oid:'" << oid << "' val: '" << value << "'";
    int vallen = value.size();
    ctrl->ldctl_value.bv_len = vallen;
    if (vallen) {
        ctrl->ldctl_value.bv_val = (char *) malloc(vallen);
        memcpy(ctrl->ldctl_value.bv_val, value.data(), vallen);
    } else {
        ctrl->ldctl_value.bv_val = 0;
    }
    ctrl->ldctl_iscritical = critical;
    ctrl->ldctl_oid = strdup(oid.toUtf8());

    uint i = 0;

    if (ctrls == 0) {
        ctrls = (LDAPControl **)malloc(2 * sizeof(LDAPControl *));
        ctrls[ 0 ] = 0;
        ctrls[ 1 ] = 0;
    } else {
        while (ctrls[ i ] != 0) {
            i++;
        }
        ctrls[ i + 1 ] = 0;
        ctrls =
            (LDAPControl **)realloc(ctrls, (i + 2) * sizeof(LDAPControl *));
    }
    ctrls[ i ] = ctrl;
    *pctrls = ctrls;
}

static void createControls(LDAPControl ***pctrls, const LdapControls &ctrls)
{
    for (int i = 0; i < ctrls.count(); ++i) {
        addControlOp(pctrls, ctrls[i].oid(), ctrls[i].value(), ctrls[i].critical());
    }
}

static void extractControls(LdapControls &ctrls, LDAPControl **pctrls)
{
    LDAPControl *ctrl;
    LdapControl control;
    int i = 0;

    while (pctrls[i]) {
        ctrl = pctrls[ i ];
        control.setOid(QString::fromUtf8(ctrl->ldctl_oid));
        control.setValue(QByteArray(ctrl->ldctl_value.bv_val,
                                    ctrl->ldctl_value.bv_len));
        control.setCritical(ctrl->ldctl_iscritical);
        ctrls.append(control);
        i++;
    }
}

int LdapOperation::bind(const QByteArray &creds, SASL_Callback_Proc *saslproc, void *data)
{
    return d->bind(creds, saslproc, data, true);
}

int LdapOperation::bind_s(SASL_Callback_Proc *saslproc, void *data)
{
    return d->bind(QByteArray(), saslproc, data, false);
}

int LdapOperation::search(const LdapDN &base, LdapUrl::Scope scope,
                          const QString &filter, const QStringList &attributes)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    char **attrs = 0;
    int msgid;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int count = attributes.count();
    if (count > 0) {
        attrs = static_cast<char **>(malloc((count + 1) * sizeof(char *)));
        for (int i = 0; i < count; i++) {
            attrs[i] = strdup(attributes.at(i).toUtf8());
        }
        attrs[count] = 0;
    }

    int lscope = LDAP_SCOPE_BASE;
    switch (scope) {
    case LdapUrl::Base:
        lscope = LDAP_SCOPE_BASE;
        break;
    case LdapUrl::One:
        lscope = LDAP_SCOPE_ONELEVEL;
        break;
    case LdapUrl::Sub:
        lscope = LDAP_SCOPE_SUBTREE;
        break;
    }

    qDebug() << "asyncSearch() base=\"" << base.toString()
             << "\" scope=" << (int)scope
             << "filter=\"" << filter
             << "\" attrs=" << attributes;
    int retval =
        ldap_search_ext(ld, base.toString().toUtf8().data(), lscope,
                        filter.isEmpty() ? QByteArray("objectClass=*").data() :
                        filter.toUtf8().data(),
                        attrs, 0, serverctrls, clientctrls, 0,
                        d->mConnection->sizeLimit(), &msgid);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    // free the attributes list again
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            free(attrs[i]);
        }
        free(attrs);
    }

    if (retval == 0) {
        retval = msgid;
    }
    return retval;
}

int LdapOperation::add(const LdapObject &object)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    int msgid;
    LDAPMod **lmod = 0;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    for (LdapAttrMap::ConstIterator it = object.attributes().begin();
            it != object.attributes().end(); ++it) {
        QString attr = it.key();
        for (LdapAttrValue::ConstIterator it2 = (*it).begin(); it2 != (*it).end(); ++it2) {
            addModOp(&lmod, 0, attr, &(*it2));
        }
    }

    int retval =
        ldap_add_ext(ld, object.dn().toString().toUtf8().data(), lmod, serverctrls,
                     clientctrls, &msgid);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);
    ldap_mods_free(lmod, 1);
    if (retval == 0) {
        retval = msgid;
    }
    return retval;
}

int LdapOperation::add_s(const LdapObject &object)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPMod **lmod = 0;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    for (LdapAttrMap::ConstIterator it = object.attributes().begin();
            it != object.attributes().end(); ++it) {
        QString attr = it.key();
        for (LdapAttrValue::ConstIterator it2 = (*it).begin(); it2 != (*it).end(); ++it2) {
            addModOp(&lmod, 0, attr, &(*it2));
        }
    }

    int retval =
        ldap_add_ext_s(ld, object.dn().toString().toUtf8().data(), lmod, serverctrls,
                       clientctrls);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);
    ldap_mods_free(lmod, 1);
    return retval;
}

int LdapOperation::add(const LdapDN &dn, const ModOps &ops)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    int msgid;
    LDAPMod **lmod = 0;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    for (int i = 0; i < ops.count(); ++i) {
        for (int j = 0; j < ops[i].values.count(); ++j) {
            addModOp(&lmod, 0, ops[i].attr, &ops[i].values[j]);
        }
    }

    int retval =
        ldap_add_ext(ld, dn.toString().toUtf8().data(), lmod, serverctrls,
                     clientctrls, &msgid);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);
    ldap_mods_free(lmod, 1);
    if (retval == 0) {
        retval = msgid;
    }
    return retval;
}

int LdapOperation::add_s(const LdapDN &dn, const ModOps &ops)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPMod **lmod = 0;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    for (int i = 0; i < ops.count(); ++i) {
        for (int j = 0; j < ops[i].values.count(); ++j) {
            addModOp(&lmod, 0, ops[i].attr, &ops[i].values[j]);
        }
    }
    qDebug() << dn.toString();
    int retval =
        ldap_add_ext_s(ld, dn.toString().toUtf8().data(), lmod, serverctrls,
                       clientctrls);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);
    ldap_mods_free(lmod, 1);
    return retval;
}

int LdapOperation::rename(const LdapDN &dn, const QString &newRdn,
                          const QString &newSuperior, bool deleteold)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    int msgid;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int retval = ldap_rename(ld, dn.toString().toUtf8().data(), newRdn.toUtf8().data(),
                             newSuperior.isEmpty() ? (char *) 0 : newSuperior.toUtf8().data(),
                             deleteold, serverctrls, clientctrls, &msgid);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    if (retval == 0) {
        retval = msgid;
    }
    return retval;
}

int LdapOperation::rename_s(const LdapDN &dn, const QString &newRdn,
                            const QString &newSuperior, bool deleteold)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int retval = ldap_rename_s(ld, dn.toString().toUtf8().data(), newRdn.toUtf8().data(),
                               newSuperior.isEmpty() ? (char *) 0 : newSuperior.toUtf8().data(),
                               deleteold, serverctrls, clientctrls);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    return retval;
}

int LdapOperation::del(const LdapDN &dn)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    int msgid;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int retval =
        ldap_delete_ext(ld, dn.toString().toUtf8().data(), serverctrls, clientctrls, &msgid);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    if (retval == 0) {
        retval = msgid;
    }
    return retval;
}

int LdapOperation::del_s(const LdapDN &dn)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int retval = ldap_delete_ext_s(ld, dn.toString().toUtf8().data(), serverctrls, clientctrls);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    return retval;
}

int LdapOperation::modify(const LdapDN &dn, const ModOps &ops)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *)d->mConnection->handle();

    int msgid;
    LDAPMod **lmod = 0;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    for (int i = 0; i < ops.count(); ++i) {
        int mtype = 0;
        switch (ops[i].type) {
        case Mod_None:
            mtype = 0;
            break;
        case Mod_Add:
            mtype = LDAP_MOD_ADD;
            break;
        case Mod_Replace:
            mtype = LDAP_MOD_REPLACE;
            break;
        case Mod_Del:
            mtype = LDAP_MOD_DELETE;
            break;
        }
        addModOp(&lmod, mtype, ops[i].attr, 0);
        for (int j = 0; j < ops[i].values.count(); ++j) {
            addModOp(&lmod, mtype, ops[i].attr, &ops[i].values[j]);
        }
    }

    int retval =
        ldap_modify_ext(ld, dn.toString().toUtf8().data(), lmod, serverctrls, clientctrls, &msgid);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);
    ldap_mods_free(lmod, 1);
    if (retval == 0) {
        retval = msgid;
    }
    return retval;
}

int LdapOperation::modify_s(const LdapDN &dn, const ModOps &ops)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPMod **lmod = 0;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    for (int i = 0; i < ops.count(); ++i) {
        int mtype = 0;
        switch (ops[i].type) {
        case Mod_None:
            mtype = 0;
            break;
        case Mod_Add:
            mtype = LDAP_MOD_ADD;
            break;
        case Mod_Replace:
            mtype = LDAP_MOD_REPLACE;
            break;
        case Mod_Del:
            mtype = LDAP_MOD_DELETE;
            break;
        }
        addModOp(&lmod, mtype, ops[i].attr, 0);
        for (int j = 0; j < ops[i].values.count(); ++j) {
            addModOp(&lmod, mtype, ops[i].attr, &ops[i].values[j]);
        }
    }

    int retval =
        ldap_modify_ext_s(ld, dn.toString().toUtf8().data(), lmod, serverctrls, clientctrls);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);
    ldap_mods_free(lmod, 1);
    return retval;
}

int LdapOperation::compare(const LdapDN &dn, const QString &attr, const QByteArray &value)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();
    int msgid;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int vallen = value.size();
    BerValue *berval;
    berval = (BerValue *) malloc(sizeof(BerValue));
    berval -> bv_val = (char *) malloc(vallen);
    berval -> bv_len = vallen;
    memcpy(berval -> bv_val, value.data(), vallen);

    int retval = ldap_compare_ext(ld, dn.toString().toUtf8().data(), attr.toUtf8().data(), berval,
                                  serverctrls, clientctrls, &msgid);

    ber_bvfree(berval);
    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    if (retval == 0) {
        retval = msgid;
    }
    return retval;
}

int LdapOperation::compare_s(const LdapDN &dn, const QString &attr, const QByteArray &value)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int vallen = value.size();
    BerValue *berval;
    berval = (BerValue *) malloc(sizeof(BerValue));
    berval -> bv_val = (char *) malloc(vallen);
    berval -> bv_len = vallen;
    memcpy(berval -> bv_val, value.data(), vallen);

    int retval = ldap_compare_ext_s(ld, dn.toString().toUtf8().data(), attr.toUtf8().data(), berval,
                                    serverctrls, clientctrls);

    ber_bvfree(berval);
    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    return retval;
}

int LdapOperation::exop(const QString &oid, const QByteArray &data)
{
    Q_ASSERT(d->mConnection);
#if defined(HAVE_LDAP_EXTENDED_OPERATION) && defined(HAVE_LDAP_EXTENDED_OPERATION_PROTOTYPE)
    LDAP *ld = (LDAP *) d->mConnection->handle();
    int msgid;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int vallen = data.size();
    BerValue *berval;
    berval = (BerValue *) malloc(sizeof(BerValue));
    berval -> bv_val = (char *) malloc(vallen);
    berval -> bv_len = vallen;
    memcpy(berval -> bv_val, data.data(), vallen);

    int retval = ldap_extended_operation(ld, oid.toUtf8().data(), berval,
                                         serverctrls, clientctrls, &msgid);

    ber_bvfree(berval);
    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    if (retval == 0) {
        retval = msgid;
    }
    return retval;
#else
    qCritical() << "Your LDAP client libraries don't support extended operations.";
    return -1;
#endif
}

int LdapOperation::exop_s(const QString &oid, const QByteArray &data)
{
#if defined(HAVE_LDAP_EXTENDED_OPERATION) && defined(HAVE_LDAP_EXTENDED_OPERATION_PROTOTYPE)
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();
    BerValue *retdata;
    char *retoid;

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int vallen = data.size();
    BerValue *berval;
    berval = (BerValue *) malloc(sizeof(BerValue));
    berval -> bv_val = (char *) malloc(vallen);
    berval -> bv_len = vallen;
    memcpy(berval -> bv_val, data.data(), vallen);

    int retval = ldap_extended_operation_s(ld, oid.toUtf8().data(), berval,
                                           serverctrls, clientctrls, &retoid, &retdata);

    ber_bvfree(berval);
    ber_bvfree(retdata);
    free(retoid);
    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    return retval;
#else
    qCritical() << "Your LDAP client libraries don't support extended operations.";
    return -1;
#endif
}

int LdapOperation::abandon(int id)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPControl **serverctrls = 0, **clientctrls = 0;
    createControls(&serverctrls, d->mServerCtrls);
    createControls(&serverctrls, d->mClientCtrls);

    int retval = ldap_abandon_ext(ld, id, serverctrls, clientctrls);

    ldap_controls_free(serverctrls);
    ldap_controls_free(clientctrls);

    return retval;
}

int LdapOperation::waitForResult(int id, int msecs)
{
    Q_ASSERT(d->mConnection);
    LDAP *ld = (LDAP *) d->mConnection->handle();

    LDAPMessage *msg;
    int rescode;

    QTime stopWatch;
    stopWatch.start();
    int attempt(1);
    int timeout(0);

    do {
        // Calculate the timeout value to use and assign it to a timeval structure
        // see man select (2) for details
        timeout = kldap_timeout_value(msecs, stopWatch.elapsed());
        qDebug() << "(" << id << "," << msecs
                 << "): Waiting" << timeout
                 << "msecs for result. Attempt #" << attempt++;
        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        // Wait for a result
        rescode = ldap_result(ld, id, 0, timeout < 0 ? 0 : &tv, &msg);
        if (rescode == -1) {
            return -1;
        }
        // Act on the return code
        if (rescode != 0) {
            // Some kind of result is available for processing
            return d->processResult(rescode, msg);
        }
    } while (msecs == -1 || stopWatch.elapsed() < msecs);

    return 0; //timeout
}

#else

int LdapOperation::bind(const QByteArray &creds, SASL_Callback_Proc *saslproc, void *data)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::bind_s(SASL_Callback_Proc *saslproc, void *data)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::search(const LdapDN &base, LdapUrl::Scope scope,
                          const QString &filter, const QStringList &attributes)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::add(const LdapObject &object)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::add_s(const LdapObject &object)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::add(const LdapDN &dn, const ModOps &ops)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::add_s(const LdapDN &dn, const ModOps &ops)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::rename(const LdapDN &dn, const QString &newRdn,
                          const QString &newSuperior, bool deleteold)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::rename_s(const LdapDN &dn, const QString &newRdn,
                            const QString &newSuperior, bool deleteold)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::del(const LdapDN &dn)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::del_s(const LdapDN &dn)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::modify(const LdapDN &dn, const ModOps &ops)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::modify_s(const LdapDN &dn, const ModOps &ops)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::compare(const LdapDN &dn, const QString &attr, const QByteArray &value)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::exop(const QString &oid, const QByteArray &data)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::compare_s(const LdapDN &dn, const QString &attr, const QByteArray &value)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::exop_s(const QString &oid, const QByteArray &data)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::waitForResult(int id, int msecs)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

int LdapOperation::abandon(int id)
{
    qCritical() << "LDAP support not compiled";
    return -1;
}

#endif
