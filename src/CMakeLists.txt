# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckSymbolExists)

check_include_files(sys/time.h HAVE_SYS_TIME_H)

set(kldap_EXTRA_LIBS)

if(Ldap_FOUND)
  set(kldap_EXTRA_LIBS Ldap::Ldap)
  if(WIN32)
    set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} ws2_32)
  endif()
  set(CMAKE_REQUIRED_INCLUDES lber.h ldap.h)
  set(CMAKE_REQUIRED_LIBRARIES Ldap::Ldap)
  check_function_exists(ldap_start_tls_s HAVE_LDAP_START_TLS_S)
  check_function_exists(ldap_initialize HAVE_LDAP_INITIALIZE)
  check_function_exists(ber_memfree HAVE_BER_MEMFREE)
  check_function_exists(ldap_unbind_ext HAVE_LDAP_UNBIND_EXT)
  check_function_exists(ldap_extended_operation HAVE_LDAP_EXTENDED_OPERATION)
  check_function_exists(ldap_extended_operation_s HAVE_LDAP_EXTENDED_OPERATION_S)
endif()

set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} Sasl2::Sasl2)

configure_file(kldap_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/kldap_config.h)

########### next target ###############

add_library(KF5Ldap)
add_library(KF5::Ldap ALIAS KF5Ldap)

target_sources(KF5Ldap PRIVATE
  core/ber.cpp
  core/ldif.cpp
  core/ldapurl.cpp
  core/ldapserver.cpp
  core/ldapobject.cpp
  core/ldapconnection.cpp
  core/ldapoperation.cpp
  core/ldapcontrol.cpp
  core/ldapsearch.cpp
  core/ldapdn.cpp
  core/ldif.h
  core/ldapsearch.h
  core/w32-ldap-help.h
  core/ldapurl.h
  core/ldapcontrol.h
  core/ber.h
  core/ldapdefs.h
  core/ldapconnection.h
  core/ldapdn.h
  core/ldapoperation.h
  core/ldapserver.h
  core/ldapobject.h


  widgets/ldapconfigwidget.cpp
  widgets/addhostdialog.cpp
  widgets/ldapclient.cpp
  widgets/ldapclientsearch.cpp
  widgets/ldapclientsearchconfig.cpp
  widgets/ldapconfigurewidget.cpp
  widgets/ldapclientsearchconfigreadconfigjob.cpp
  widgets/ldapclientsearchconfigwriteconfigjob.cpp
  widgets/ldapwidgetitem_p.cpp
  widgets/ldapwidgetitemreadconfigserverjob.cpp
  widgets/ldapsearchclientreadconfigserverjob.cpp

  widgets/ldapclientsearchconfig.h
  widgets/ldapclientsearchconfigreadconfigjob.h
  widgets/ldapclient.h
  widgets/addhostdialog.h
  widgets/ldapwidgetitem_p.h
  widgets/ldapconfigwidget.h
  widgets/ldapclientsearch.h
  widgets/ldapclientsearchconfigwriteconfigjob.h
  widgets/ldapconfigurewidget.h
  widgets/ldapsearchclientreadconfigserverjob.h
  widgets/ldapwidgetitemreadconfigserverjob.h
   )
 
ecm_qt_declare_logging_category(KF5Ldap HEADER ldap_debug.h IDENTIFIER LDAP_LOG CATEGORY_NAME org.kde.pim.ldap
        DESCRIPTION "kldaplib (kldap)"
        OLD_CATEGORY_NAMES log_ldap
        EXPORT KLDAP
    )

ecm_qt_declare_logging_category(KF5Ldap HEADER ldapclient_debug.h IDENTIFIER LDAPCLIENT_LOG CATEGORY_NAME org.kde.pim.ldapclient
        DESCRIPTION "ldapclient (libkdepim)"
        OLD_CATEGORY_NAMES log_ldapclient
        EXPORT KLDAP
    )

if (COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(KF5Ldap PROPERTIES UNITY_BUILD ON)
endif()
generate_export_header(KF5Ldap BASE_NAME kldap)



target_link_libraries(KF5Ldap
PRIVATE
  Qt::Widgets
  KF${KF_MAJOR_VERSION}::I18n
  KF${KF_MAJOR_VERSION}::WidgetsAddons
  KF${KF_MAJOR_VERSION}::ConfigCore
  KF${KF_MAJOR_VERSION}::CoreAddons
  KF${KF_MAJOR_VERSION}::KIOCore
  KF${KF_MAJOR_VERSION}::ConfigGui
  ${kldap_EXTRA_LIBS}
)

target_link_libraries(KF5Ldap PRIVATE qt${QT_MAJOR_VERSION}keychain)

target_include_directories(KF5Ldap INTERFACE "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR_KF}/KLDAP>")
target_include_directories(KF5Ldap PUBLIC "$<BUILD_INTERFACE:${KLdap_SOURCE_DIR}/src/core;${KLdap_BINARY_DIR}/src>")

set_target_properties(KF5Ldap PROPERTIES
    VERSION ${KLDAP_VERSION}
    SOVERSION ${KLDAP_SOVERSION}
    EXPORT_NAME Ldap
)

install(TARGETS KF5Ldap EXPORT KF5LdapTargets ${KF_INSTALL_TARGETS_DEFAULT_ARGS})

########### install files ###############

ecm_generate_headers(KLdapCore_CamelCase_HEADERS
  HEADER_NAMES
  Ber
  LdapConnection
  LdapControl
  LdapDN
  LdapObject
  LdapOperation
  LdapSearch
  LdapServer
  LdapDefs
  LdapUrl
  Ldif
  RELATIVE core
  PREFIX KLDAP
  REQUIRED_HEADERS KLdapCore_HEADERS
)

ecm_generate_headers(KLdapWidgets_CamelCase_HEADERS
  HEADER_NAMES
  LdapConfigWidget
  LdapClientSearchConfig
  LdapClientSearch
  AddHostDialog
  LdapClient
  LdapConfigureWidget
  LdapClientSearchConfigWriteConfigJob
  LdapClientSearchConfigReadConfigJob
  LdapSearchClientReadConfigServerJob
  RELATIVE widgets
  PREFIX KLDAP
  REQUIRED_HEADERS KLdapWidgets_HEADERS
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/kldap_export.h
    ${KLdapCore_HEADERS}
    ${KLdapWidgets_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF}/KLDAP/kldap
    COMPONENT Devel
)

install(FILES
    ${KLdapCore_CamelCase_HEADERS}
    ${KLdapWidgets_CamelCase_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF}/KLDAP/KLDAP/
    COMPONENT Devel
)

if (BUILD_QCH)
    ecm_add_qch(
        KF5LDap_QCH
        NAME KLDap
        BASE_NAME KF5LDap
        VERSION ${PIM_VERSION}
        ORG_DOMAIN org.kde

        SOURCES # using only public headers, to cover only public API
            ${KLdapCore_HEADERS}
            ${KLdapWidgets_HEADERS}
        MD_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md"
        #IMAGE_DIRS "${CMAKE_SOURCE_DIR}/docs/pics"
        LINK_QCHS
            Qt${QT_MAJOR_VERSION}Core_QCH
            Qt${QT_MAJOR_VERSION}Gui_QCH
            Qt${QT_MAJOR_VERSION}Widgets_QCH
        INCLUDE_DIRS
            ${CMAKE_CURRENT_BINARY_DIR}
        BLANK_MACROS
            KLDAP_EXPORT
        TAGFILE_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        QCH_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        COMPONENT Devel
    )
endif()

ecm_generate_pri_file(BASE_NAME Ldap LIB_NAME KF5Ldap FILENAME_VAR PRI_FILENAME INCLUDE_INSTALL_DIR ${KDE_INSTALL_INCLUDEDIR_KF}/KLDAP/)
install(FILES ${PRI_FILENAME} DESTINATION ${ECM_MKSPECS_INSTALL_DIR})

