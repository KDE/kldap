/*
  This file is part of libkldap.
  Copyright (c) 2006 Sean Harmer <sh@theharmers.co.uk>

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

#ifndef KLDAP_LDAPMODELPRIVATE_H
#define KLDAP_LDAPMODELPRIVATE_H

#include "ldapconnection.h"
#include "ldapdn.h"
#include "ldapmodel.h"
#include "ldapobject.h"

namespace KLDAP
{

class LdapModelDNNode;
class LdapSearch;

/**
 * @internal
 */
class LdapModel::LdapModelPrivate
{
public:
    enum SearchType {
        NotSearching = 0,
        NamingContexts,
        BaseDN,
        ChildObjects
    };

    explicit LdapModelPrivate(LdapModel *parent);
    explicit LdapModelPrivate(LdapModel *parent, LdapConnection &connection);

    ~LdapModelPrivate();

    void setConnection(LdapConnection &connection);

    bool search(const LdapDN &searchBase,
                LdapUrl::Scope scope = LdapUrl::Sub,
                const QString &filter = QString(),
                const QStringList &attributes = QStringList(),
                int pagesize = 0);

    LdapModelDNNode *rootNode()
    {
        return m_root;
    }
    LdapSearch *search()
    {
        return m_search;
    }

    LdapObjects &searchResults()
    {
        return m_searchResultObjects;
    }
    const LdapObjects &searchResults() const
    {
        return m_searchResultObjects;
    }

    void recreateRootItem();

    void setBaseDN(const LdapDN &baseDN)
    {
        m_baseDN = baseDN;
    }
    LdapDN &baseDN()
    {
        return m_baseDN;
    }
    const LdapDN &baseDN() const
    {
        return m_baseDN;
    }

    void setSearchType(SearchType t, LdapModelDNNode *item = 0);

    SearchType searchType()
    {
        return m_searchType;
    }
    LdapModelDNNode *searchItem()
    {
        return m_searchItem;
    }

    void createConnections();
    void populateRootToBaseDN();
    void gotSearchResult(KLDAP::LdapSearch *search);
    void gotSearchData(KLDAP::LdapSearch *search, const KLDAP::LdapObject &obj);

private:
    LdapModel *m_parent;
    LdapModelDNNode *m_root;
    LdapSearch *m_search;
    LdapObjects m_searchResultObjects;
    LdapDN m_baseDN;
    SearchType m_searchType;
    LdapModelDNNode *m_searchItem;
};

}
#endif
