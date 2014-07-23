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

#include "ldapmodel_p.h"
#include "ldapmodelnode_p.h"
#include "ldapsearch.h"

#include <qdebug.h>

using namespace KLDAP;

LdapModel::LdapModelPrivate::LdapModelPrivate(LdapModel *parent)
    : m_parent(parent),
      m_root(new LdapModelDNNode),
      m_search(new LdapSearch),
      m_searchResultObjects(),
      m_baseDN(),
      m_searchType(NotSearching),
      m_searchItem(0)
{
}

LdapModel::LdapModelPrivate::LdapModelPrivate(LdapModel *parent, LdapConnection &connection)
    : m_parent(parent),
      m_root(new LdapModelDNNode),
      m_search(new LdapSearch(connection)),
      m_searchResultObjects(),
      m_baseDN(),
      m_searchType(NotSearching),
      m_searchItem(0)
{
}

LdapModel::LdapModelPrivate::~LdapModelPrivate()
{
    delete m_root;

    delete m_search;
}

void LdapModel::LdapModelPrivate::setConnection(LdapConnection &connection)
{
    m_search->setConnection(connection);
}

bool LdapModel::LdapModelPrivate::search(const LdapDN &searchBase,
        LdapUrl::Scope scope,
        const QString &filter,
        const QStringList &attributes,
        int pagesize)
{
    return m_search->search(searchBase, scope, filter, attributes, pagesize);
}

void LdapModel::LdapModelPrivate::setSearchType(SearchType t, LdapModelDNNode *item)
{
    //qDebug() << "item =" << item;
    m_searchType = t;
    m_searchItem = item;
}

void LdapModel::LdapModelPrivate::recreateRootItem()
{
    //qDebug();
    delete m_root;
    m_root = new LdapModelDNNode;
    //qDebug() << "&m_root =" << &m_root;
}

void LdapModel::LdapModelPrivate::createConnections()
{
    connect(search(), SIGNAL(result(KLDAP::LdapSearch *)),
            m_parent, SLOT(gotSearchResult(KLDAP::LdapSearch *)));
    connect(search(), SIGNAL(data(KLDAP::LdapSearch *, KLDAP::LdapObject)),
            m_parent, SLOT(gotSearchData(KLDAP::LdapSearch *, KLDAP::LdapObject)));
}

void LdapModel::LdapModelPrivate::populateRootToBaseDN()
{
    //qDebug();

    if (baseDN().isEmpty()) {
        // Query the server for the base DN
        //qDebug() << "Searching for the baseDN";
        setSearchType(LdapModelPrivate::NamingContexts, rootNode());
        search(LdapDN(), LdapUrl::Base, QString(), QStringList() << QLatin1String("namingContexts"));
        return;
    }

    // Start a search for the details of the baseDN object
    //qDebug() << "Searching for attributes of the baseDN";
    searchResults().clear();
    setSearchType(LdapModelPrivate::BaseDN, rootNode());
    search(baseDN(), LdapUrl::Base, QString(), QStringList() << QLatin1String("dn") << QLatin1String("objectClass"));
}

void LdapModel::LdapModelPrivate::gotSearchResult(KLDAP::LdapSearch *search)
{
    Q_UNUSED(search);
    qDebug();

    switch (searchType()) {
    case LdapModelPrivate::NamingContexts: {
        // Set the baseDN
        QString baseDN;
        if (!searchResults().isEmpty() &&
                searchResults().at(0).hasAttribute(QLatin1String("namingContexts"))) {
            baseDN = QLatin1String(searchResults().at(0).value(QLatin1String("namingContexts")));
            //qDebug() << "Found baseDN =" << baseDN;
        }
        setBaseDN(LdapDN(baseDN));

        // Flag that we are no longer searching for the baseDN
        setSearchType(LdapModelPrivate::NotSearching);

        // Populate the root item
        populateRootToBaseDN();

        break;
    }
    case LdapModelPrivate::BaseDN: {
        //qDebug() << "Found details of the baseDN object."
        //         << "Creating objects down to this level.";

        // Get the baseDN LdapObject
        LdapObject baseDNObj = searchResults().at(0);

        // How many levels of items do we need to create?
        int depth = baseDNObj.dn().depth();

        // Create items that represent objects down to the baseDN
        LdapModelDNNode *parent = rootNode();
        LdapModelDNNode *item = 0;
        for (int i = 0; i < depth; ++i) {
            QString dn = baseDN().toString(i);
            qDebug() << "Creating item for DN :" << dn;

            //LdapObject obj( dn );
            item = new LdapModelDNNode(parent, LdapDN(dn));
            parent = item;
        }

        // Store the search result
        if (item) {
            item->setLdapObject(baseDNObj);
        }

        // Flag that we are no longer searching
        setSearchType(LdapModelPrivate::NotSearching);
        //emit( layoutChanged() );

        // Let the world know we are ready for action
        emit m_parent->ready();

        break;
    }
    case LdapModelPrivate::ChildObjects: {
        //qDebug() << "Found" << searchResults().size() << "child objects";

        if (searchResults().size() != 0) {
            // Create an index for the soon-to-be-a-parent item
            LdapModelDNNode *parentNode = searchItem();
            int r = parentNode->row();
            QModelIndex parentIndex = m_parent->createIndex(r, 0, parentNode);

            m_parent->beginInsertRows(parentIndex, 0, searchResults().size());
            for (int i = 0; i < searchResults().size(); i++) {
                LdapObject object = searchResults().at(i);
                LdapModelDNNode *item = new LdapModelDNNode(parentNode, object.dn());
                item->setLdapObject(object);
            }

            m_parent->endInsertRows();
            emit m_parent->layoutChanged();
        }

        // Flag that we are no longer searching
        setSearchType(LdapModelPrivate::NotSearching);

        break;
    }
    default:
        break;
    }
}

void LdapModel::LdapModelPrivate::gotSearchData(KLDAP::LdapSearch *search,
        const KLDAP::LdapObject &obj)
{
    Q_UNUSED(search);
    //qDebug();
    //qDebug() << "Object:";
    //qDebug() << obj.toString();
    searchResults().append(obj);
}
