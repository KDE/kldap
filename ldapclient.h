/* kldapclient.h - LDAP access
 *      Copyright (C) 2002 Klarälvdalens Datakonsult AB
 *
 *      Author: Steffen Hansen <hansen@kde.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef KLDAP_LDAPCLIENT_H
#define KLDAP_LDAPCLIENT_H

#include "kldap_export.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>

class KConfig;
class KConfigGroup;
class KJob;

namespace KLDAP {

class LdapObject;
class LdapServer;

/**
 * @since 4.5
 */
class KLDAP_EXPORT LdapClient : public QObject
{
  Q_OBJECT

  public:
    explicit LdapClient( int clientNumber, QObject* parent = 0, const char* name = 0 );
    virtual ~LdapClient();

    /*! returns true if there is a query running */
    bool isActive() const;

    int clientNumber() const;
    int completionWeight() const;
    void setCompletionWeight( int );

    const KLDAP::LdapServer& server() const;
    void setServer( const KLDAP::LdapServer &server );

    /*! Set the attributes that should be
     * returned, or an empty list if
     * all attributes are wanted
     */
    void setAttributes( const QStringList& attrs );

    /*! Return the attributes that should be
     * returned, or an empty list if
     * all attributes are wanted
     */
    QStringList attributes() const;

    void setScope( const QString scope );

    /*!
     * Start the query with filter filter
     */
    void startQuery( const QString& filter );

    /*!
     * Abort a running query
     */
    void cancelQuery();

  Q_SIGNALS:
    /*! Emitted when the query is done */
    void done();

    /*! Emitted in case of error */
    void error( const QString& );

    /*! Emitted once for each object returned
     * from the query
     */
    void result( const KLDAP::LdapClient &client, const KLDAP::LdapObject& );

  private:
    //@cond PRIVATE
    class Private;
    Private* const d;

    Q_PRIVATE_SLOT( d, void slotData( KIO::Job*, const QByteArray& ) )
    Q_PRIVATE_SLOT( d, void slotInfoMessage( KJob*, const QString&, const QString& ) )
    Q_PRIVATE_SLOT( d, void slotDone() )
    //@endcond
};

/**
 * Structure describing one result returned by a LDAP query
 * @since 4.5
 */
struct LdapResult
{
  QString name;     ///< full name
  QStringList email;    ///< emails
  int clientNumber; ///< for sorting in a ldap-only lookup
  int completionWeight; ///< for sorting in a completion list
};
typedef QList<LdapResult> LdapResultList;

/**
 * @since 4.5
 */
class KLDAP_EXPORT LdapClientSearch : public QObject
{
  Q_OBJECT

  public:
    explicit LdapClientSearch( QObject *parent = 0 );

    ~LdapClientSearch();

    static KConfig *config();
    static void readConfig( KLDAP::LdapServer &server, const KConfigGroup &config, int num, bool active );
    static void writeConfig( const KLDAP::LdapServer &server, KConfigGroup &config, int j, bool active );

    void startSearch( const QString& txt );
    void cancelSearch();
    bool isAvailable() const;
    void updateCompletionWeights();

    QList<LdapClient*> clients() const;

  Q_SIGNALS:
    /// Results, assembled as "Full Name <email>"
    /// (This signal can be emitted many times)
    void searchData( const QStringList& );
    /// Another form for the results, with separate fields
    /// (This signal can be emitted many times)
    void searchData( const KLDAP::LdapResultList& );
    void searchDone();

  private:
    //@cond PRIVATE
    class Private;
    Private* const d;

    Q_PRIVATE_SLOT( d, void slotLDAPResult( const KLDAP::LdapClient&, const KLDAP::LdapObject& ) )
    Q_PRIVATE_SLOT( d, void slotLDAPError( const QString& ) )
    Q_PRIVATE_SLOT( d, void slotLDAPDone() )
    Q_PRIVATE_SLOT( d, void slotDataTimer() )
    Q_PRIVATE_SLOT( d, void slotFileChanged( const QString& ) )
    //@endcond
};

}

#endif
