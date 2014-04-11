include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckSymbolExists)

# Reactivate it
remove_definitions(-DQT_NO_CAST_FROM_BYTEARRAY)

check_include_files(sys/time.h HAVE_SYS_TIME_H)

set(kldap_EXTRA_LIBS)

if(LDAP_FOUND)
  set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} ${LDAP_LIBRARIES})
  set(HAVE_LDAP_H)
  set(CMAKE_REQUIRED_INCLUDES lber.h ldap.h)
  set(CMAKE_REQUIRED_LIBRARIES ${LDAP_LIBRARIES})
  check_function_exists(ldap_start_tls_s HAVE_LDAP_START_TLS_S)
  check_function_exists(ldap_initialize HAVE_LDAP_INITIALIZE)
  check_function_exists(ber_memfree HAVE_BER_MEMFREE)
  check_function_exists(ldap_unbind_ext HAVE_LDAP_UNBIND_EXT)
  check_function_exists(ldap_extended_operation HAVE_LDAP_EXTENDED_OPERATION)
  check_function_exists(ldap_extended_operation_s HAVE_LDAP_EXTENDED_OPERATION_S)
  check_symbol_exists(ldap_extended_operation ldap.h HAVE_LDAP_EXTENDED_OPERATION_PROTOTYPE)
  check_symbol_exists(ldap_extended_operation_s ldap.h HAVE_LDAP_EXTENDED_OPERATION_S_PROTOTYPE)
endif()

if(Sasl2_FOUND)
  set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} ${Sasl2_LIBRARIES})
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/kldap_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/kldap_config.h)

########### next target ###############

set(kldap_LIB_SRCS
  ber.cpp
  ldif.cpp
  ldapurl.cpp
  ldapserver.cpp
  ldapobject.cpp
  ldapconnection.cpp
  ldapoperation.cpp
  ldapcontrol.cpp
  ldapsearch.cpp
  ldapconfigwidget.cpp
  ldapdn.cpp
  ldapmodelnode_p.cpp
  ldapmodel.cpp
  ldapmodel_p.cpp
  ldapstructureproxymodel.cpp
  ldapattributeproxymodel.cpp
)

add_library(KF5KLdap ${kldap_LIB_SRCS})

generate_export_header(KF5KLdap BASE_NAME kldap)

add_library(KF5::KLdap ALIAS KF5KLdap)

# TODO KF5: we only need KDEUI here, remove KCM, KIO and KABC
target_link_libraries(KF5KLdap
  KF5::CoreAddons
  KF5::KIOCore
  KF5::KDELibs4Support
  KF5::KCMUtils
  ${kldap_EXTRA_LIBS}
  KF5::Abc
)

target_include_directories(KF5KLdap INTERFACE "$<INSTALL_INTERFACE:${INCLUDE_INSTALL_DIR}/kldap>")
target_include_directories(KF5KLdap PUBLIC "$<BUILD_INTERFACE:${KLdap_SOURCE_DIR}/src;${KLdap_BINARY_DIR}/src>")
if(LDAP_FOUND)
  target_include_directories(KF5KLdap INTERFACE "$<INSTALL_INTERFACE:${LDAP_INCLUDE_DIR}>")
endif()
if(Sasl2_FOUND)
  target_include_directories(KF5KLdap INTERFACE "$<INSTALL_INTERFACE:${Sasl2_INCLUDE_DIRS}>")
endif()

set_target_properties(KF5KLdap PROPERTIES
    VERSION ${KLDAP_VERSION_STRING}
    SOVERSION ${KLDAP_SOVERSION}
    EXPORT_NAME KLdap
)


install(TARGETS KF5KLdap EXPORT KF5KLdapTargets ${INSTALL_TARGETS_DEFAULT_ARGS})

########### install files ###############

ecm_generate_headers(KLdap_CamelCase_HEADERS
  HEADER_NAMES
  Ber
  LdapAttributeProxyModel
  LdapConfigWidget
  LdapConnection
  LdapControl
  LdapDN
  LdapModel
  LdapObject
  LdapOperation
  LdapSearch
  LdapServer
  LdapStructureProxyModel
  LdapUrl
  Ldif

  REQUIRED_HEADERS KLdap_HEADERS
  PREFIX KLdap
)

install(FILES
    ${KLdap_CamelCase_HEADERS}
    DESTINATION ${INCLUDE_INSTALL_DIR}/KLDAP
    COMPONENT Devel
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/kldap_export.h
  ${KLdap_HEADERS}
  ldapdefs.h
  DESTINATION ${INCLUDE_INSTALL_DIR}/kldap COMPONENT Devel
)
