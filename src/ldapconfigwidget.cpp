/*
  This file is part of libkldap.
  Copyright (c) 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
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

#include "ldapconfigwidget.h"
#include "ldapsearch.h"

#include <qprogressdialog.h>
#include <kcombobox.h>
#include <qdebug.h>
#include <klocalizedstring.h>
#include <klineedit.h>
#include <kmessagebox.h>

#include <QtCore/QObject>
#include <QCheckBox>
#include <QGroupBox>
#include <QLabel>
#include <QLayout>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>

using namespace KLDAP;

class LdapConfigWidget::Private
{
  public:
    Private( LdapConfigWidget *parent )
      : mParent( parent ), mFeatures( W_ALL ), mProg( 0 )
    {
      mainLayout = new QGridLayout( mParent );
      mainLayout->setMargin( 0 );
    }

    void setLDAPPort();
    void setLDAPSPort();
    void setAnonymous( bool on );
    void setSimple( bool on );
    void setSASL( bool on );
    void queryDNClicked();
    void queryMechClicked();
    void loadData( LdapSearch *search, const LdapObject &object );
    void loadResult( LdapSearch *search );
    void sendQuery();
    void initWidget();

    LdapConfigWidget *mParent;
    WinFlags mFeatures;
    QStringList mQResult;
    QString mAttr;

    QLineEdit *mUser;
    QLineEdit *mPassword;
    QLineEdit *mHost;
    QSpinBox  *mPort, *mVersion, *mSizeLimit, *mTimeLimit, *mPageSize;
    QLineEdit *mDn, *mBindDn, *mRealm;
    QLineEdit *mFilter;
    QRadioButton *mAnonymous,*mSimple,*mSASL;
    QCheckBox *mSubTree;
    QPushButton *mEditButton;
    QPushButton *mQueryMech;
    QRadioButton *mSecNo,*mSecTLS,*mSecSSL;
    KComboBox *mMech;

    bool mCancelled;
    QProgressDialog *mProg;

    QGridLayout *mainLayout;
};

void LdapConfigWidget::Private::initWidget()
{
  QLabel *label;

  mUser = mPassword = mHost = mDn = mBindDn = mRealm = mFilter = 0;
  mPort = mVersion = mTimeLimit = mSizeLimit = 0;
  mAnonymous = mSimple = mSASL = mSecNo = mSecTLS = mSecSSL = 0;
  mEditButton =  mQueryMech = 0;
  mPageSize = 0;
  mMech = 0;
  int row = 0;
  int col;

  if ( mFeatures & W_USER ) {
    label = new QLabel( i18n( "User:" ), mParent );
    mUser = new QLineEdit( mParent );
    mUser->setObjectName( QLatin1String("kcfg_ldapuser") );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mUser, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_BINDDN ) {
    label = new QLabel( i18n( "Bind DN:" ), mParent );
    mBindDn = new QLineEdit( mParent );
    mBindDn->setObjectName( QLatin1String("kcfg_ldapbinddn") );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mBindDn, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_REALM ) {
    label = new QLabel( i18n( "Realm:" ), mParent );
    mRealm = new QLineEdit( mParent );
    mRealm->setObjectName( QLatin1String("kcfg_ldaprealm") );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mRealm, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_PASS ) {
    label = new QLabel( i18n( "Password:" ), mParent );
    mPassword = new QLineEdit( mParent );
    mPassword->setObjectName( QLatin1String("kcfg_ldappassword") );
    mPassword->setEchoMode( QLineEdit::Password );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mPassword, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_HOST ) {
    label = new QLabel( i18n( "Host:" ), mParent );
    mHost = new QLineEdit( mParent );
    mHost->setObjectName( QLatin1String("kcfg_ldaphost") );
    mParent->connect(mHost, SIGNAL(textChanged(QString)), SIGNAL(hostNameChanged(QString)));
    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mHost, row, 1, 1, 3 );
    row++;
  }

  col = 0;
  if ( mFeatures & W_PORT ) {
    label = new QLabel( i18n( "Port:" ), mParent );
    mPort = new QSpinBox( mParent );
    mPort->setRange( 0, 65535 );
    mPort->setObjectName( QLatin1String("kcfg_ldapport") );
    mPort->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mPort->setValue( 389 );

    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mPort, row, col+1 );
    col += 2;
  }

  if ( mFeatures & W_VER ) {
    label = new QLabel( i18n( "LDAP version:" ), mParent );
    mVersion = new QSpinBox( mParent );
    mVersion->setRange( 2, 3 );
    mVersion->setObjectName( QLatin1String("kcfg_ldapver") );
    mVersion->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mVersion->setValue( 3 );
    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mVersion, row, col+1 );
  }
  if ( mFeatures & ( W_PORT | W_VER ) ) {
    row++;
  }

  col = 0;
  if ( mFeatures & W_SIZELIMIT ) {
    label = new QLabel( i18n( "Size limit:" ), mParent );
    mSizeLimit = new QSpinBox( mParent );
    mSizeLimit->setRange( 0, 9999999 );
    mSizeLimit->setObjectName( QLatin1String("kcfg_ldapsizelimit") );
    mSizeLimit->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mSizeLimit->setValue( 0 );
    mSizeLimit->setSpecialValueText( i18nc( "default ldap size limit", "Default" ) );
    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mSizeLimit, row, col+1 );
    col += 2;
  }

  if ( mFeatures & W_TIMELIMIT ) {
    label = new QLabel( i18n( "Time limit:" ), mParent );
    mTimeLimit = new QSpinBox( mParent );
    mTimeLimit->setRange( 0, 9999999 );
    mTimeLimit->setObjectName( QLatin1String("kcfg_ldaptimelimit") );
    mTimeLimit->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mTimeLimit->setValue( 0 );
    mTimeLimit->setSuffix( i18n( " sec" ) );
    mTimeLimit->setSpecialValueText( i18nc( "default ldap time limit", "Default" ) );
    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mTimeLimit, row, col+1 );
  }
  if ( mFeatures & ( W_SIZELIMIT | W_TIMELIMIT ) ) {
    row++;
  }

  if ( mFeatures & W_PAGESIZE ) {
    label = new QLabel( i18n( "Page size:" ), mParent );
    mPageSize = new QSpinBox( mParent );
    mPageSize->setRange( 0, 9999999 );
    mPageSize->setObjectName( QLatin1String("kcfg_ldappagesize") );
    mPageSize->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mPageSize->setValue( 0 );
    mPageSize->setSpecialValueText( i18n( "No paging" ) );
    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mPageSize, row++, 1 );
  }

  if ( mFeatures & W_DN ) {
    label = new QLabel( i18nc( "Distinguished Name", "DN:" ), mParent );
    mDn = new QLineEdit( mParent );
    mDn->setObjectName( QLatin1String("kcfg_ldapdn") );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mDn, row, 1, 1, 1 );
    //without host query doesn't make sense
    if ( mHost ) {
      QPushButton *dnquery = new QPushButton( i18n( "Query Server" ), mParent );
      connect( dnquery, SIGNAL(clicked()), mParent, SLOT(queryDNClicked()) );
      mainLayout->addWidget( dnquery, row, 2, 1, 1 );
    }
    row++;
  }

  if ( mFeatures & W_FILTER ) {
    label = new QLabel( i18n( "Filter:" ), mParent );
    mFilter = new QLineEdit( mParent );
    mFilter->setObjectName( QLatin1String("kcfg_ldapfilter") );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mFilter, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_SECBOX ) {
    QGroupBox *btgroup = new QGroupBox( i18n( "Security" ), mParent );
    QHBoxLayout *hbox = new QHBoxLayout;
    btgroup->setLayout( hbox );
    mSecNo = new QRadioButton( i18nc( "@option:radio set no security", "No" ), btgroup );
    mSecNo->setObjectName( QLatin1String("kcfg_ldapnosec") );
    hbox->addWidget( mSecNo );
    mSecTLS = new QRadioButton( i18nc( "@option:radio use TLS security", "TLS" ), btgroup );
    mSecTLS->setObjectName( QLatin1String("kcfg_ldaptls") );
    hbox->addWidget( mSecTLS );
    mSecSSL = new QRadioButton( i18nc( "@option:radio use SSL security", "SSL" ), btgroup );
    mSecSSL->setObjectName( QLatin1String("kcfg_ldapssl") );
    hbox->addWidget( mSecSSL );
    mainLayout->addWidget( btgroup, row, 0, 1, 4 );

    connect( mSecNo, SIGNAL(clicked()), mParent, SLOT(setLDAPPort()) );
    connect( mSecTLS, SIGNAL(clicked()), mParent, SLOT(setLDAPPort()) );
    connect( mSecSSL, SIGNAL(clicked()), mParent, SLOT(setLDAPSPort()) );

    mSecNo->setChecked( true );
    row++;
  }

  if ( mFeatures & W_AUTHBOX ) {

    QGroupBox *authbox =
      new QGroupBox( i18n( "Authentication" ), mParent );
    QVBoxLayout *vbox = new QVBoxLayout;
    authbox->setLayout( vbox );
    QHBoxLayout *hbox = new QHBoxLayout;
    vbox->addLayout( hbox );

    mAnonymous =
      new QRadioButton( i18nc( "@option:radio anonymous authentication", "Anonymous" ), authbox );
    mAnonymous->setObjectName( QLatin1String("kcfg_ldapanon") );
    hbox->addWidget( mAnonymous );
    mSimple =
      new QRadioButton( i18nc( "@option:radio simple authentication", "Simple" ), authbox );
    mSimple->setObjectName( QLatin1String("kcfg_ldapsimple") );
    hbox->addWidget( mSimple );
    mSASL =
      new QRadioButton( i18nc( "@option:radio SASL authentication", "SASL" ), authbox );
    mSASL->setObjectName( QLatin1String("kcfg_ldapsasl") );
    hbox->addWidget( mSASL );

    hbox = new QHBoxLayout;
    vbox->addLayout( hbox );
    label = new QLabel( i18n( "SASL mechanism:" ), authbox );
    hbox->addWidget( label );
    mMech = new KComboBox( false, authbox );
    mMech->setObjectName( QLatin1String("kcfg_ldapsaslmech") );
    mMech->setEditable( true );
    mMech->addItem( QLatin1String("DIGEST-MD5") );
    mMech->addItem( QLatin1String("GSSAPI") );
    mMech->addItem( QLatin1String("PLAIN") );
    hbox->addWidget( mMech );

    //without host query doesn't make sense
    if ( mHost ) {
      mQueryMech = new QPushButton( i18n( "Query Server" ), authbox );
      hbox->addWidget( mQueryMech );
      connect( mQueryMech, SIGNAL(clicked()), mParent, SLOT(queryMechClicked()) );
    }

    mainLayout->addWidget( authbox, row, 0, 2, 4 );

    connect( mAnonymous, SIGNAL(toggled(bool)), mParent, SLOT(setAnonymous(bool)) );
    connect( mSimple, SIGNAL(toggled(bool)), mParent, SLOT(setSimple(bool)) );
    connect( mSASL, SIGNAL(toggled(bool)), mParent, SLOT(setSASL(bool)) );

    mAnonymous->setChecked( true );
  }
}

void LdapConfigWidget::Private::sendQuery()
{
  LdapServer _server( mParent->server() );

  mQResult.clear();
  mCancelled = true;

  if ( mAttr == QLatin1String("supportedsaslmechanisms") ) {
    _server.setAuth( LdapServer::Anonymous );
  }

  LdapUrl _url( _server.url() );

  _url.setDn( LdapDN( QLatin1String("") ) );
  _url.setAttributes( QStringList( mAttr ) );
  _url.setScope( LdapUrl::Base );

  qDebug() << "sendQuery url:" << _url.prettyUrl();

  LdapSearch search;
  connect( &search, SIGNAL(data(KLDAP::LdapSearch*,KLDAP::LdapObject)),
           mParent, SLOT(loadData(KLDAP::LdapSearch*,KLDAP::LdapObject)) );
  connect( &search, SIGNAL(result(KLDAP::LdapSearch*)),
           mParent, SLOT(loadResult(KLDAP::LdapSearch*)) );

  if ( !search.search( _url ) ) {
    KMessageBox::error( mParent, search.errorString() );
    return;
  }

  if ( mProg == 0 ) {
    mProg = new QProgressDialog( mParent );
    mProg->setWindowTitle( i18n( "LDAP Query" ) );
    mProg->setModal( true );
  }
  mProg->setLabelText( _url.prettyUrl() );
  mProg->setMaximum(1);
  mProg->setMinimum( 0 );
  mProg->setValue( 0 );
  mProg->exec();
  if ( mCancelled ) {
    qDebug() << "query canceled!";
    search.abandon();
  } else {
    if ( search.error() ) {
      if ( search.errorString().isEmpty() ) {
        KMessageBox::error( mParent, i18nc( "%1 is a url to ldap server", "Unknown error connecting %1", _url.prettyUrl() ) );
      } else {
        KMessageBox::error( mParent, search.errorString() );
      }
    }
  }
}

void LdapConfigWidget::Private::queryMechClicked()
{
  mAttr = QLatin1String("supportedsaslmechanisms");
  sendQuery();
  if ( !mQResult.isEmpty() ) {
    mQResult.sort();
    mMech->clear();
    mMech->addItems( mQResult );
  }
}

void LdapConfigWidget::Private::queryDNClicked()
{
  mAttr = QLatin1String("namingcontexts");
  sendQuery();
  if ( !mQResult.isEmpty() ) {
    mDn->setText( mQResult.first() );
  }
}

void LdapConfigWidget::Private::loadData( LdapSearch *, const LdapObject &object )
{
  qDebug() << "object:" << object.toString();
  mProg->setValue( mProg->value() + 1 );
  LdapAttrMap::ConstIterator end( object.attributes().constEnd() );
  for ( LdapAttrMap::ConstIterator it = object.attributes().constBegin();
        it != end; ++it ) {
    LdapAttrValue::ConstIterator end2( ( *it ).constEnd() );
    for ( LdapAttrValue::ConstIterator it2 = ( *it ).constBegin();
          it2 != end2; ++it2 ) {
      mQResult.push_back( QString::fromUtf8( *it2 ) );
    }
  }
}

void LdapConfigWidget::Private::loadResult( LdapSearch *search )
{
  Q_UNUSED( search );
  mCancelled = false;
  mProg->close();
}

void LdapConfigWidget::Private::setAnonymous( bool on )
{
  if ( !on ) {
    return;
  }
  if ( mUser ) {
    mUser->setEnabled( false );
  }
  if ( mPassword ) {
    mPassword->setEnabled( false );
  }
  if ( mBindDn ) {
    mBindDn->setEnabled( false );
  }
  if ( mRealm ) {
    mRealm->setEnabled( false );
  }
  if ( mMech ) {
    mMech->setEnabled( false );
  }
  if ( mQueryMech ) {
    mQueryMech->setEnabled( false );
  }
}

void LdapConfigWidget::Private::setSimple( bool on )
{
  if ( !on ) {
    return;
  }
  if ( mUser ) {
    mUser->setEnabled( false );
  }
  if ( mPassword ) {
    mPassword->setEnabled( true );
  }
  if ( mBindDn ) {
    mBindDn->setEnabled( true );
  }
  if ( mRealm ) {
    mRealm->setEnabled( false );
  }
  if ( mMech ) {
    mMech->setEnabled( false );
  }
  if ( mQueryMech ) {
    mQueryMech->setEnabled( false );
  }
}

void LdapConfigWidget::Private::setSASL( bool on )
{
  if ( !on ) {
    return;
  }
  if ( mUser ) {
    mUser->setEnabled( true );
  }
  if ( mPassword ) {
    mPassword->setEnabled( true );
  }
  if ( mBindDn ) {
    mBindDn->setEnabled( true );
  }
  if ( mRealm ) {
    mRealm->setEnabled( true );
  }
  if ( mMech ) {
    mMech->setEnabled( true );
  }
  if ( mQueryMech ) {
    mQueryMech->setEnabled( true );
  }
}

void LdapConfigWidget::Private::setLDAPPort()
{
  if ( mPort ) {
    mPort->setValue( 389 );
  }
}

void LdapConfigWidget::Private::setLDAPSPort()
{
  if ( mPort ) {
    mPort->setValue( 636 );
  }
}

LdapConfigWidget::LdapConfigWidget( QWidget *parent, Qt::WindowFlags fl )
  : QWidget( parent, fl ), d( new Private( this ) )
{
}

LdapConfigWidget::LdapConfigWidget( LdapConfigWidget::WinFlags flags,
                                    QWidget *parent, Qt::WindowFlags fl )
  : QWidget( parent, fl ), d( new Private( this ) )
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

void LdapConfigWidget::setUrl( const LdapUrl &url )
{
  LdapServer _server;
  _server.setUrl( url );
  setServer( _server );
}

LdapServer LdapConfigWidget::server() const
{
  LdapServer _server;
  if ( d->mSecSSL && d->mSecSSL->isChecked() ) {
    _server.setSecurity( LdapServer::SSL );
  } else if ( d->mSecTLS && d->mSecTLS->isChecked() ) {
    _server.setSecurity( LdapServer::TLS );
  } else {
    _server.setSecurity( LdapServer::None );
  }

  if ( d->mUser ) {
    _server.setUser( d->mUser->text() );
  }
  if ( d->mBindDn ) {
    _server.setBindDn( d->mBindDn->text() );
  }
  if ( d->mPassword ) {
    _server.setPassword( d->mPassword->text() );
  }
  if ( d->mRealm ) {
    _server.setRealm( d->mRealm->text() );
  }
  if ( d->mHost ) {
    _server.setHost( d->mHost->text() );
  }
  if ( d->mPort ) {
    _server.setPort( d->mPort->value() );
  }
  if ( d->mDn ) {
    _server.setBaseDn( LdapDN( d->mDn->text() ) );
  }
  if ( d->mFilter ) {
    _server.setFilter( d->mFilter->text() );
  }
  if ( d->mVersion ) {
    _server.setVersion( d->mVersion->value() );
  }
  if ( d->mSizeLimit && d->mSizeLimit->value() != 0 ) {
    _server.setSizeLimit( d->mSizeLimit->value() );
  }
  if ( d->mTimeLimit && d->mTimeLimit->value() != 0 ) {
    _server.setTimeLimit( d->mTimeLimit->value() );
  }
  if ( d->mPageSize && d->mPageSize->value() != 0 ) {
    _server.setPageSize( d->mPageSize->value() );
  }
  if ( d->mAnonymous && d->mAnonymous->isChecked() ) {
    _server.setAuth( LdapServer::Anonymous );
  } else if ( d->mSimple && d->mSimple->isChecked() ) {
    _server.setAuth( LdapServer::Simple );
  } else if ( d->mSASL && d->mSASL->isChecked() ) {
    _server.setAuth( LdapServer::SASL );
    _server.setMech( d->mMech->currentText() );
  }
  return _server;
}

void LdapConfigWidget::setServer( const LdapServer &server )
{
  switch ( server.security() ) {
  case LdapServer::SSL:
    if ( d->mSecSSL ) {
      d->mSecSSL->setChecked( true );
    }
    break;
  case LdapServer::TLS:
    if ( d->mSecTLS ) {
      d->mSecTLS->setChecked( true );
    }
    break;
  case LdapServer::None:
    if ( d->mSecNo ) {
      d->mSecNo->setChecked( true );
    }
    break;
  }

  switch ( server.auth() ) {
  case LdapServer::Anonymous:
    if ( d->mAnonymous ) {
      d->mAnonymous->setChecked( true );
    }
    break;
  case LdapServer::Simple:
    if ( d->mSimple ) {
      d->mSimple->setChecked( true );
    }
    break;
  case LdapServer::SASL:
    if ( d->mSASL ) {
      d->mSASL->setChecked( true );
    }
    break;
  }

  setUser( server.user() );
  setBindDn( server.bindDn() );
  setPassword( server.password() );
  setRealm( server.realm() );
  setHost( server.host() );
  setPort( server.port() );
  setFilter( server.filter() );
  setDn( server.baseDn() );
  setVersion( server.version() );
  setSizeLimit( server.sizeLimit() );
  setTimeLimit( server.timeLimit() );
  setPageSize( server.pageSize() );
  setMech( server.mech() );
}

void LdapConfigWidget::setUser( const QString &user )
{
  if ( d->mUser ) {
    d->mUser->setText( user );
  }
}

QString LdapConfigWidget::user() const
{
  return d->mUser ? d->mUser->text() : QString();
}

void LdapConfigWidget::setPassword( const QString &password )
{
  if ( d->mPassword ) {
    d->mPassword->setText( password );
  }
}

QString LdapConfigWidget::password() const
{
  return d->mPassword ? d->mPassword->text() : QString();
}

void LdapConfigWidget::setBindDn( const QString &binddn )
{
  if ( d->mBindDn ) {
    d->mBindDn->setText( binddn );
  }
}

QString LdapConfigWidget::bindDn() const
{
  return d->mBindDn ? d->mBindDn->text() : QString();
}

void LdapConfigWidget::setRealm( const QString &realm )
{
  if ( d->mRealm ) {
    d->mRealm->setText( realm );
  }
}

QString LdapConfigWidget::realm() const
{
  return d->mRealm ? d->mRealm->text() : QString();
}

void LdapConfigWidget::setHost( const QString &host )
{
  if ( d->mHost ) {
    d->mHost->setText( host );
  }
}

QString LdapConfigWidget::host() const
{
  return d->mHost ? d->mHost->text() : QString();
}

void LdapConfigWidget::setPort( int port )
{
  if ( d->mPort ) {
    d->mPort->setValue( port );
  }
}

int LdapConfigWidget::port() const
{
  return d->mPort ? d->mPort->value() : 389;
}

void LdapConfigWidget::setVersion( int version )
{
  if ( d->mVersion ) {
    d->mVersion->setValue( version );
  }
}

int LdapConfigWidget::version() const
{
  return d->mVersion ? d->mVersion->value() : 3;
}

void LdapConfigWidget::setDn( const LdapDN &dn )
{
  if ( d->mDn ) {
    d->mDn->setText( dn.toString() );
  }
}

LdapDN LdapConfigWidget::dn() const
{
  return d->mDn ? LdapDN( d->mDn->text() ) : LdapDN();
}

void LdapConfigWidget::setFilter( const QString &filter )
{
  if ( d->mFilter ) {
    d->mFilter->setText( filter );
  }
}

QString LdapConfigWidget::filter() const
{
  return d->mFilter ? d->mFilter->text() : QString();
}

void LdapConfigWidget::setMech( const QString &mech )
{
  if ( d->mMech == 0 ) {
    return;
  }
  if ( !mech.isEmpty() ) {
    int i = 0;
    while ( i < d->mMech->count() ) {
      if ( d->mMech->itemText( i ) == mech ) {
        break;
      }
      i++;
    }
    if ( i == d->mMech->count() ) {
      d->mMech->addItem( mech );
    }
    d->mMech->setCurrentIndex( i );
  }
}

QString LdapConfigWidget::mech() const
{
  return d->mMech ? d->mMech->currentText() : QString();
}

void LdapConfigWidget::setSecurity( Security security )
{
  switch ( security ) {
  case None:
    d->mSecNo->setChecked( true );
    break;
  case SSL:
    d->mSecSSL->setChecked( true );
    break;
  case TLS:
    d->mSecTLS->setChecked( true );
    break;
  }
}

LdapConfigWidget::Security LdapConfigWidget::security() const
{
  if ( d->mSecTLS->isChecked() ) {
    return TLS;
  }
  if ( d->mSecSSL->isChecked() ) {
    return SSL;
  }
  return None;
}

void LdapConfigWidget::setAuth( Auth auth )
{
  switch ( auth ) {
  case Anonymous:
    d->mAnonymous->setChecked( true );
    break;
  case Simple:
    d->mSimple->setChecked( true );
    break;
  case SASL:
    d->mSASL->setChecked( true );
    break;
  }
}

LdapConfigWidget::Auth LdapConfigWidget::auth() const
{
  if ( d->mSimple->isChecked() ) {
    return Simple;
  }
  if ( d->mSASL->isChecked() ) {
    return SASL;
  }
  return Anonymous;
}

void LdapConfigWidget::setSizeLimit( int sizelimit )
{
  if ( d->mSizeLimit ) {
    d->mSizeLimit->setValue( sizelimit );
  }
}

int LdapConfigWidget::sizeLimit() const
{
  return d->mSizeLimit ? d->mSizeLimit->value() : 0;
}

void LdapConfigWidget::setTimeLimit( int timelimit )
{
  if ( d->mTimeLimit ) {
    d->mTimeLimit->setValue( timelimit );
  }
}

int LdapConfigWidget::timeLimit() const
{
  return d->mTimeLimit ? d->mTimeLimit->value() : 0;
}

void LdapConfigWidget::setPageSize( int pagesize )
{
  if ( d->mPageSize ) {
    d->mPageSize->setValue( pagesize );
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

void LdapConfigWidget::setFeatures( LdapConfigWidget::WinFlags features )
{
  d->mFeatures = features;

  // First delete all the child widgets.
  // FIXME: I hope it's correct
  QList<QObject*> ch = children();
  const int numberOfChild( ch.count() );
  for ( int i = 0; i < numberOfChild; ++i ) {
    QWidget *widget = dynamic_cast<QWidget*>( ch[ i ] );
    if ( widget && widget->parent() == this ) {
      delete ( widget );
    }
  }

  // Re-create child widgets according to the new flags
  d->initWidget();
}

#include "moc_ldapconfigwidget.cpp"
