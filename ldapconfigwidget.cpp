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

#include <QCheckBox>
#include <QGroupBox>
#include <QLabel>
#include <QLayout>
#include <QProgressDialog>
#include <QPushButton>
#include <QObject>
#include <QRadioButton>
#include <QSpinBox>

#include <kacceleratormanager.h>
#include <kcombobox.h>
#include <kdebug.h>
#include <klocale.h>
#include <klineedit.h>
#include <kmessagebox.h>

#include "ldapconfigwidget.h"

using namespace KLDAP;

LdapConfigWidget::LdapConfigWidget( QWidget* parent,
                                    Qt::WFlags fl ) : QWidget( parent, fl )
{
  mProg = 0;
  mFeatures = W_ALL;
  mainLayout = new QGridLayout( this );
}

LdapConfigWidget::LdapConfigWidget( LdapConfigWidget::WinFlags flags, QWidget* parent,
                                    Qt::WFlags fl ) : QWidget( parent, fl )
{
  mFeatures = flags;
  mProg = 0;
  mainLayout = new QGridLayout( this );
  initWidget();
}

LdapConfigWidget::~LdapConfigWidget()
{
}

void LdapConfigWidget::initWidget()
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
    label = new QLabel( i18n( "User:" ), this );
    mUser = new KLineEdit( this );
    mUser->setObjectName( "kcfg_ldapuser" );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mUser, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_BINDDN ) {
    label = new QLabel( i18n( "Bind DN:" ), this );
    mBindDn = new KLineEdit( this );
    mBindDn->setObjectName( "kcfg_ldapbinddn" );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mBindDn, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_REALM ) {
    label = new QLabel( i18n( "Realm:" ), this );
    mRealm = new KLineEdit( this );
    mRealm->setObjectName("kcfg_ldaprealm" );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mRealm, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_PASS ) {
    label = new QLabel( i18n( "Password:" ), this );
    mPassword = new KLineEdit( this );
    mPassword->setObjectName( "kcfg_ldappassword" );
    mPassword->setEchoMode( KLineEdit::Password );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mPassword, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_HOST ) {
    label = new QLabel( i18n( "Host:" ), this );
    mHost = new KLineEdit( this );
    mHost->setObjectName( "kcfg_ldaphost" );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mHost, row, 1, 1, 3 );
    row++;
  }

  col = 0;
  if ( mFeatures & W_PORT ) {
    label = new QLabel( i18n( "Port:" ), this );
    mPort = new QSpinBox( this );
    mPort->setRange( 0, 65535 );
    mPort->setObjectName("kcfg_ldapport" );
    mPort->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mPort->setValue( 389 );

    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mPort, row, col+1 );
    col += 2;
  }

  if ( mFeatures & W_VER ) {
    label = new QLabel( i18n( "LDAP version:" ), this );
    mVersion = new QSpinBox( this );
    mVersion->setRange( 2, 3 );
    mVersion->setObjectName( "kcfg_ldapver" );
    mVersion->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mVersion->setValue( 3 );
    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mVersion, row, col+1 );
  }
  if ( mFeatures & ( W_PORT | W_VER ) ) row++;

  col = 0;
  if ( mFeatures & W_SIZELIMIT ) {
    label = new QLabel( i18n( "Size limit:" ), this );
    mSizeLimit = new QSpinBox( this );
    mSizeLimit->setRange( 0, 9999999 );
    mSizeLimit->setObjectName("kcfg_ldapsizelimit" );
    mSizeLimit->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mSizeLimit->setValue( 0 );
    mSizeLimit->setSpecialValueText( i18n("Default") );
    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mSizeLimit, row, col+1 );
    col += 2;
  }

  if ( mFeatures & W_TIMELIMIT ) {
    label = new QLabel( i18n( "Time limit:" ), this );
    mTimeLimit = new QSpinBox( this );
    mTimeLimit->setRange( 0, 9999999 );
    mTimeLimit->setObjectName("kcfg_ldaptimelimit" );
    mTimeLimit->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mTimeLimit->setValue( 0 );
    mTimeLimit->setSuffix( i18n(" sec") );
    mTimeLimit->setSpecialValueText( i18n("Default") );
    mainLayout->addWidget( label, row, col );
    mainLayout->addWidget( mTimeLimit, row, col+1 );
  }
  if ( mFeatures & ( W_SIZELIMIT | W_TIMELIMIT ) ) row++;

  if ( mFeatures & W_PAGESIZE ) {
    label = new QLabel( i18n( "Page size:" ), this );
    mPageSize = new QSpinBox( this );
    mPageSize->setRange( 0, 9999999 );
    mPageSize->setObjectName("kcfg_ldappagesize" );
    mPageSize->setSizePolicy( QSizePolicy( QSizePolicy::Maximum, QSizePolicy::Preferred ) );
    mPageSize->setValue( 0 );
    mPageSize->setSpecialValueText( i18n("No paging") );
    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mPageSize, row++, 1 );
  }

  if ( mFeatures & W_DN ) {
    label = new QLabel( i18nc( "Distinguished Name", "DN:" ), this );
    mDn = new KLineEdit( this);
    mDn->setObjectName("kcfg_ldapdn" );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mDn, row, 1, 1, 1 );
    //without host query doesn't make sense
    if ( mHost ) {
      QPushButton *dnquery = new QPushButton( i18n( "Query Server" ), this );
      connect( dnquery, SIGNAL( clicked() ), SLOT( mQueryDNClicked() ) );
      mainLayout->addWidget( dnquery, row, 2, 1, 1 );
    }
    row++;
  }

  if ( mFeatures & W_FILTER ) {
    label = new QLabel( i18n( "Filter:" ), this );
    mFilter = new KLineEdit( this);
    mFilter->setObjectName("kcfg_ldapfilter" );

    mainLayout->addWidget( label, row, 0 );
    mainLayout->addWidget( mFilter, row, 1, 1, 3 );
    row++;
  }

  if ( mFeatures & W_SECBOX ) {
    QGroupBox *btgroup = new QGroupBox( i18n( "Security" ), this );
    QHBoxLayout *hbox = new QHBoxLayout;
    btgroup->setLayout( hbox );
    mSecNo = new QRadioButton( i18n( "No" ), btgroup);
    mSecNo->setObjectName( "kcfg_ldapnosec" );
    hbox->addWidget( mSecNo );
    mSecTLS = new QRadioButton( i18n( "TLS" ), btgroup);
    mSecTLS->setObjectName( "kcfg_ldaptls" );
    hbox->addWidget( mSecTLS );
    mSecSSL = new QRadioButton( i18n( "SSL" ), btgroup);
    mSecSSL->setObjectName("kcfg_ldapssl" );
    hbox->addWidget( mSecSSL );
    mainLayout->addWidget( btgroup, row, 0, 1, 4 );

    connect( mSecNo, SIGNAL( clicked() ), SLOT( setLDAPPort() ) );
    connect( mSecTLS, SIGNAL( clicked() ), SLOT( setLDAPPort() ) );
    connect( mSecSSL, SIGNAL( clicked() ), SLOT( setLDAPSPort( ) ) );

    mSecNo->setChecked( true );
    row++;
  }

  if ( mFeatures & W_AUTHBOX ) {

    QGroupBox *authbox =
      new QGroupBox( i18n( "Authentication" ), this );
    QVBoxLayout *vbox = new QVBoxLayout;
    authbox->setLayout( vbox );
    QHBoxLayout *hbox = new QHBoxLayout;
    vbox->addLayout( hbox );

    mAnonymous = new QRadioButton( i18n( "Anonymous" ), authbox);
    mAnonymous->setObjectName("kcfg_ldapanon" );
    hbox->addWidget( mAnonymous );
    mSimple = new QRadioButton( i18n( "Simple" ), authbox);
    mSimple->setObjectName( "kcfg_ldapsimple" );
    hbox->addWidget( mSimple );
    mSASL = new QRadioButton( i18n( "SASL" ), authbox);
    mSASL->setObjectName("kcfg_ldapsasl" );
    hbox->addWidget( mSASL );

    hbox = new QHBoxLayout;
    vbox->addLayout( hbox );
    label = new QLabel( i18n( "SASL mechanism:" ), authbox );
    hbox->addWidget( label );
    mMech = new KComboBox( false, authbox);
    mMech->setObjectName("kcfg_ldapsaslmech");
    mMech->setEditable( true );
    mMech->addItem( "DIGEST-MD5" );
    mMech->addItem( "GSSAPI" );
    mMech->addItem( "PLAIN" );
    hbox->addWidget( mMech );

    //without host query doesn't make sense
    if ( mHost ) {
      mQueryMech = new QPushButton( i18n( "Query Server" ), authbox );
      hbox->addWidget( mQueryMech );
      connect( mQueryMech, SIGNAL( clicked() ), SLOT( mQueryMechClicked() ) );
    }

    mainLayout->addWidget( authbox, row, 0, 2, 4 );

    connect( mAnonymous, SIGNAL( toggled(bool) ), SLOT( setAnonymous(bool) ) );
    connect( mSimple, SIGNAL( toggled(bool) ), SLOT( setSimple(bool) ) );
    connect( mSASL, SIGNAL( toggled(bool) ), SLOT( setSASL(bool) ) );

    mAnonymous->setChecked( true );
  }

}

void LdapConfigWidget::loadData( KIO::Job*, const QByteArray& d )
{
  Ldif::ParseValue ret;

  if ( d.size() ) {
    mLdif.setLdif( d );
  } else {
    mLdif.endLdif();
  }
  do {
    ret = mLdif.nextItem();
    if ( ret == Ldif::Item && mLdif.attr().toLower() == mAttr ) {
      mProg->setValue( mProg->value() + 1 );
      mQResult.push_back( QString::fromUtf8( mLdif.value(), mLdif.value().size() ) );
    }
  } while ( ret != Ldif::MoreData );
}

void LdapConfigWidget::loadResult( KJob* job)
{
  int error = job->error();
  if ( error && error != KIO::ERR_USER_CANCELED )
    mErrorMsg = job->errorString();
  else
    mErrorMsg = "";

  mCancelled = false;
  mProg->close();
}

void LdapConfigWidget::sendQuery()
{
  LdapUrl _url;

  mQResult.clear();
  mCancelled = true;

  _url.setProtocol( ( mSecSSL && mSecSSL->isChecked() ) ? "ldaps" : "ldap" );
  if ( mHost ) _url.setHost( mHost->text() );
  if ( mPort ) _url.setPort( mPort->value() );
  _url.setDn( "" );
  _url.setAttributes( QStringList( mAttr ) );
  _url.setScope( LdapUrl::Base );
  if ( mVersion ) _url.setExtension( "x-ver", QString::number( mVersion->value() ) );
  if ( mSecTLS && mSecTLS->isChecked() ) _url.setExtension( "x-tls", "" );

  kDebug(5700) << "sendQuery url: " << _url.prettyUrl() << endl;
  mLdif.startParsing();
  KIO::Job *job = KIO::get( _url, true, false );
  job->addMetaData("no-auth-prompt","true");
  connect( job, SIGNAL( data( KIO::Job*, const QByteArray& ) ),
    this, SLOT( loadData( KIO::Job*, const QByteArray& ) ) );
  connect( job, SIGNAL( result( KJob* ) ),
    this, SLOT( loadResult( KJob* ) ) );

  if ( mProg == NULL )
  {
    mProg = new QProgressDialog( this );
    mProg->setWindowTitle( i18n("LDAP Query") );
    mProg->setModal( true );
  }
  mProg->setLabelText( _url.prettyUrl() );
  mProg->setRange( 0, 1 );
  mProg->setValue( 0 );
  mProg->exec();
  if ( mCancelled ) {
    kDebug(5700) << "query canceled!" << endl;
    job->kill( KJob::Quietly );
  } else {
    if ( !mErrorMsg.isEmpty() ) KMessageBox::error( this, mErrorMsg );
  }
}

void LdapConfigWidget::mQueryMechClicked()
{
  mAttr = "supportedsaslmechanisms";
  sendQuery();
  if ( !mQResult.isEmpty() ) {
    mQResult.sort();
    mMech->clear();
    mMech->addItems( mQResult );
  }
}

void LdapConfigWidget::mQueryDNClicked()
{
  mAttr = "namingcontexts";
  sendQuery();
  if ( !mQResult.isEmpty() ) mDn->setText( mQResult.first() );
}

void LdapConfigWidget::setAnonymous( bool on )
{
  if ( !on ) return;
  if ( mUser ) mUser->setEnabled(false);
  if ( mPassword ) mPassword->setEnabled(false);
  if ( mBindDn ) mBindDn->setEnabled(false);
  if ( mRealm ) mRealm->setEnabled(false);
  if ( mMech ) mMech->setEnabled(false);
  if ( mQueryMech ) mQueryMech->setEnabled(false);
}

void LdapConfigWidget::setSimple( bool on )
{
  if ( !on ) return;
  if ( mUser ) mUser->setEnabled(false);
  if ( mPassword ) mPassword->setEnabled(true);
  if ( mBindDn ) mBindDn->setEnabled(true);
  if ( mRealm ) mRealm->setEnabled(false);
  if ( mMech ) mMech->setEnabled(false);
  if ( mQueryMech ) mQueryMech->setEnabled(false);
}

void LdapConfigWidget::setSASL( bool on )
{
  if ( !on ) return;
  if ( mUser ) mUser->setEnabled(true);
  if ( mPassword ) mPassword->setEnabled(true);
  if ( mBindDn ) mBindDn->setEnabled(true);
  if ( mRealm ) mRealm->setEnabled(true);
  if ( mMech ) mMech->setEnabled(true);
  if ( mQueryMech ) mQueryMech->setEnabled(true);
}

void LdapConfigWidget::setLDAPPort()
{
  mPort->setValue( 389 );
}

void LdapConfigWidget::setLDAPSPort()
{
  mPort->setValue( 636 );
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
  if ( mSecSSL && mSecSSL->isChecked() )
    _server.setSecurity( LdapServer::SSL );
  else if ( mSecTLS && mSecTLS->isChecked() )
    _server.setSecurity( LdapServer::TLS );
  else 
    _server.setSecurity( LdapServer::None );

  if ( mUser ) _server.setUser( mUser->text() );
  if ( mBindDn ) _server.setBindDn( mBindDn->text() );
  if ( mPassword ) _server.setPassword( mPassword->text() );
  if ( mRealm ) _server.setRealm( mRealm->text() );
  if ( mHost ) _server.setHost( mHost->text() );
  if ( mPort ) _server.setPort( mPort->value() );
  if ( mDn ) _server.setBaseDn( mDn->text() );
  if ( mFilter ) _server.setFilter( mFilter->text() );
  if ( mVersion ) _server.setVersion( mVersion->value() );
  if ( mSizeLimit && mSizeLimit->value() != 0 ) 
    _server.setSizeLimit( mSizeLimit->value() );
  if ( mTimeLimit && mTimeLimit->value() != 0 )
    _server.setTimeLimit( mTimeLimit->value() );
  if ( mPageSize && mPageSize->value() != 0 )
    _server.setPageSize( mTimeLimit->value() );
  if ( mAnonymous && mAnonymous->isChecked() ) 
    _server.setAuth( LdapServer::Anonymous );
  else if ( mSimple && mSimple->isChecked() )
    _server.setAuth( LdapServer::Simple );
  else if ( mSASL && mSASL->isChecked() ) {
    _server.setAuth( LdapServer::SASL );
    _server.setMech( mMech->currentText() );
  }
  return ( _server );
}

void LdapConfigWidget::setServer( const LdapServer &server )
{
  switch ( server.security() ) {
    case LdapServer::SSL: if ( mSecSSL ) mSecSSL->setChecked( true );
    case LdapServer::TLS: if ( mSecTLS ) mSecTLS->setChecked( true );
    case LdapServer::None: if ( mSecNo ) mSecNo->setChecked( true );
  }
  switch ( server.auth() ) {
    case LdapServer::Anonymous: if ( mAnonymous ) mAnonymous->setChecked( true );
    case LdapServer::Simple: if ( mSimple ) mSimple->setChecked( true );
    case LdapServer::SASL: if ( mSASL ) mSASL->setChecked( true );
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
  if ( mUser ) mUser->setText( user );
}

QString LdapConfigWidget::user() const
{
  return ( mUser ? mUser->text() : QString() );
}

void LdapConfigWidget::setPassword( const QString &password )
{
  if ( mPassword ) mPassword->setText( password );
}

QString LdapConfigWidget::password() const
{
  return ( mPassword ? mPassword->text() : QString() );
}

void LdapConfigWidget::setBindDn( const QString &binddn )
{
  if ( mBindDn ) mBindDn->setText( binddn );
}

QString LdapConfigWidget::bindDn() const
{
  return ( mBindDn ? mBindDn->text() : QString() );
}

void LdapConfigWidget::setRealm( const QString &realm )
{
  if ( mRealm ) mRealm->setText( realm );
}

QString LdapConfigWidget::realm() const
{
  return ( mRealm ? mRealm->text() : QString() );
}

void LdapConfigWidget::setHost( const QString &host )
{
  if ( mHost ) mHost->setText( host );
}

QString LdapConfigWidget::host() const
{
  return ( mHost ? mHost->text() : QString() );
}

void LdapConfigWidget::setPort( int port )
{
  if ( mPort ) mPort->setValue( port );
}

int LdapConfigWidget::port() const
{
  return ( mPort ? mPort->value() : 389 );
}

void LdapConfigWidget::setVersion( int version )
{
  if ( mVersion ) mVersion->setValue( version );
}

int LdapConfigWidget::version() const
{
  return ( mVersion ? mVersion->value() : 3 );
}

void LdapConfigWidget::setDn( const QString &dn )
{
  if ( mDn ) mDn->setText( dn );
}

QString LdapConfigWidget::dn() const
{
  return ( mDn ? mDn->text() : QString() );
}

void LdapConfigWidget::setFilter( const QString &filter )
{
  if ( mFilter ) mFilter->setText( filter );
}

QString LdapConfigWidget::filter() const
{
  return ( mFilter ? mFilter->text() : QString() );
}

void LdapConfigWidget::setMech( const QString &mech )
{
  if ( mMech == 0 ) return;
  if ( !mech.isEmpty() ) {
    int i = 0;
    while ( i < mMech->count() ) {
      if ( mMech->itemText( i ) == mech ) break;
      i++;
    }
    if ( i == mMech->count() ) mMech->addItem( mech );
    mMech->setCurrentIndex( i );
  }
}

QString LdapConfigWidget::mech() const
{
  return ( mMech ? mMech->currentText() : QString() );
}

void LdapConfigWidget::setSecurity( Security security )
{
  switch ( security ) {
    case None: 
      mSecNo->setChecked( true );
      break;
    case SSL:
      mSecSSL->setChecked( true );
      break;
    case TLS:
      mSecTLS->setChecked( true );
      break;
  }
}

LdapConfigWidget::Security LdapConfigWidget::security() const
{
  if ( mSecTLS->isChecked() ) return TLS;
  if ( mSecSSL->isChecked() ) return SSL;
  return None;
}

void LdapConfigWidget::setAuth( Auth auth )
{
  switch ( auth ) {
    case Anonymous:
      mAnonymous->setChecked( true );
      break;
    case Simple:
      mSimple->setChecked( true );
      break;
    case SASL:
      mSASL->setChecked( true );
      break;
  }
}

LdapConfigWidget::Auth LdapConfigWidget::auth() const
{
  if ( mSimple->isChecked() ) return Simple;
  if ( mSASL->isChecked() ) return SASL;
  return Anonymous;
}

void LdapConfigWidget::setSizeLimit( int sizelimit )
{
  if ( mSizeLimit ) mSizeLimit->setValue( sizelimit );
}

int LdapConfigWidget::sizeLimit() const
{
  return ( mSizeLimit ? mSizeLimit->value() : 0 );
}

void LdapConfigWidget::setTimeLimit( int timelimit )
{
  if ( mTimeLimit ) mTimeLimit->setValue( timelimit );
}

int LdapConfigWidget::timeLimit() const
{
  return ( mTimeLimit ? mTimeLimit->value() : 0 );
}

void LdapConfigWidget::setPageSize( int pagesize )
{
  if ( mPageSize ) mPageSize->setValue( pagesize );
}

int LdapConfigWidget::pageSize() const
{
  return ( mPageSize ? mPageSize->value() : 0 );
}

LdapConfigWidget::WinFlags LdapConfigWidget::features() const
{
  return mFeatures;
}

void LdapConfigWidget::setFeatures( LdapConfigWidget::WinFlags features )
{
  mFeatures = features;

  // First delete all the child widgets.
  // FIXME: I hope it's correct
  QList<QObject*> ch = children();

  for ( int i = 0; i < ch.count(); ++i ) {
    QWidget *widget = dynamic_cast<QWidget*>( ch[ i ] );
    if ( widget && widget->parent() == this )
      delete ( widget );
  }

  // Re-create child widgets according to the new flags
  initWidget();
}

#include "ldapconfigwidget.moc"
