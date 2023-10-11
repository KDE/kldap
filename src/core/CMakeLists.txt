# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckSymbolExists)

ecm_setup_version(PROJECT VARIABLE_PREFIX KLDAPCORE
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kldap_core_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapCoreConfigVersion.cmake"
                        SOVERSION 6
)


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

configure_file(kldap_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/kldap_config.h)

########### next target ###############

add_library(KPim6LdapCore)
add_library(KPim6::LdapCore ALIAS KPim6LdapCore)

target_sources(KPim6LdapCore PRIVATE
  ber.cpp
  ldif.cpp
  ldapurl.cpp
  ldapserver.cpp
  ldapobject.cpp
  ldapconnection.cpp
  ldapoperation.cpp
  ldapcontrol.cpp
  ldapsearch.cpp
  ldapdn.cpp
  ldif.h
  ldapsearch.h
  w32-ldap-help.h
  ldapurl.h
  ldapcontrol.h
  ber.h
  ldapdefs.h
  ldapconnection.h
  ldapdn.h
  ldapoperation.h
  ldapserver.h
  ldapobject.h
   )
 
ecm_qt_declare_logging_category(KPim6LdapCore HEADER ldap_core_debug.h IDENTIFIER LDAP_LOG CATEGORY_NAME org.kde.pim.ldap.core
        DESCRIPTION "kpim6ldapcore (kldap)"
        OLD_CATEGORY_NAMES log_ldap_core
        EXPORT KLDAP
    )

if (COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(KPim6LdapCore PROPERTIES UNITY_BUILD ON)
endif()
generate_export_header(KPim6LdapCore BASE_NAME kldap_core)



target_link_libraries(KPim6LdapCore
PRIVATE
  KF6::I18n
  KF6::ConfigCore
  KF6::CoreAddons
  KF6::KIOCore
  KF6::ConfigGui
  ${kldap_EXTRA_LIBS}
)

target_link_libraries(KPim6LdapCore PRIVATE qt6keychain)

target_include_directories(KPim6LdapCore INTERFACE "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPCore>")
target_include_directories(KPim6LdapCore PUBLIC "$<BUILD_INTERFACE:${KLdap_SOURCE_DIR}/src/core;${KLdap_BINARY_DIR}/src>")

set_target_properties(KPim6LdapCore PROPERTIES
    VERSION ${KLDAPCORE_VERSION}
    SOVERSION ${KLDAPCORE_SOVERSION}
    EXPORT_NAME LdapCore
)

install(TARGETS KPim6LdapCore EXPORT KPim6LdapCoreTargets ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})

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
  PREFIX KLDAPCore
  REQUIRED_HEADERS KLdapCore_HEADERS
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/kldap_core_export.h
    ${KLdapCore_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPCore/kldapcore
    COMPONENT Devel
)

install(FILES
    ${KLdapCore_CamelCase_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPCore/KLDAPCore/
    COMPONENT Devel
)

if (BUILD_QCH)
    ecm_add_qch(
        KPim6LdapCore_QCH
	NAME KLdapCore
        BASE_NAME KPim6LdapCore
        VERSION ${PIM_VERSION}
        ORG_DOMAIN org.kde

        SOURCES # using only public headers, to cover only public API
            ${KLdapCore_HEADERS}
        MD_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md"
        #IMAGE_DIRS "${CMAKE_SOURCE_DIR}/docs/pics"
        LINK_QCHS
            Qt6Core_QCH
        INCLUDE_DIRS
            ${CMAKE_CURRENT_BINARY_DIR}
        BLANK_MACROS
            KLDAP_CORE_EXPORT
        TAGFILE_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        QCH_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        COMPONENT Devel
    )
endif()
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KPim6LdapCore")


if (BUILD_QCH)
    ecm_install_qch_export(
	    TARGETS KPim6LdapCore_QCH
	    FILE KPim6LdapCoreQchTargets.cmake
        DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
        COMPONENT Devel
    )
    set(PACKAGE_INCLUDE_QCHTARGETS "include(\"\${CMAKE_CURRENT_LIST_DIR}/KPim6LdapCoreQchTargets.cmake\")")
endif()

install(EXPORT KPim6LdapCoreTargets DESTINATION "${CMAKECONFIG_INSTALL_DIR}" FILE KPim6LdapCoreTargets.cmake NAMESPACE KPim6::)


configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/KPimLdapCoreConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapCoreConfig.cmake"
  INSTALL_DESTINATION  ${CMAKECONFIG_INSTALL_DIR}
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapCoreConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapCoreConfigVersion.cmake"
  DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
  COMPONENT Devel
)

install(FILES
   ${CMAKE_CURRENT_BINARY_DIR}/kldap_core_version.h
   DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPCore
   COMPONENT Devel
)

if(BUILD_TESTING)
    add_subdirectory(autotests)
endif()

