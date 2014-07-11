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

add_library(KF5Ldap ${kldap_LIB_SRCS})

generate_export_header(KF5Ldap BASE_NAME kldap)

add_library(KF5::Ldap ALIAS KF5Ldap)

target_link_libraries(KF5Ldap
PUBLIC
  KF5::CoreAddons
PRIVATE
  KF5::Completion
  Qt5::Widgets
  KF5::I18n
  KF5::WidgetsAddons
  ${kldap_EXTRA_LIBS}
)

target_include_directories(KF5Ldap INTERFACE "$<INSTALL_INTERFACE:${KF5_INCLUDE_INSTALL_DIR}/KLDAP>")
target_include_directories(KF5Ldap PUBLIC "$<BUILD_INTERFACE:${KLdap_SOURCE_DIR}/src;${KLdap_BINARY_DIR}/src>")
if(LDAP_FOUND)
  target_include_directories(KF5Ldap INTERFACE "$<INSTALL_INTERFACE:${LDAP_INCLUDE_DIR}>")
endif()
if(Sasl2_FOUND)
  target_include_directories(KF5Ldap INTERFACE "$<INSTALL_INTERFACE:${Sasl2_INCLUDE_DIRS}>")
endif()

set_target_properties(KF5Ldap PROPERTIES
    VERSION ${KLDAP_VERSION_STRING}
    SOVERSION ${KLDAP_SOVERSION}
    EXPORT_NAME Ldap
)


install(TARGETS KF5Ldap EXPORT KF5LdapTargets ${KF5_INSTALL_TARGETS_DEFAULT_ARGS})

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
  LdapDefs
  LdapStructureProxyModel
  LdapUrl
  Ldif
  PREFIX KLDAP
  REQUIRED_HEADERS KLdap_HEADERS
)

install(FILES
    ${KLdap_CamelCase_HEADERS}
    ${CMAKE_CURRENT_BINARY_DIR}/kldap_export.h
    ${KLdap_HEADERS}
    DESTINATION ${KF5_INCLUDE_INSTALL_DIR}/KLDAP/kldap
    COMPONENT Devel
)

install(FILES
    ${KLdap_CamelCase_HEADERS}
    DESTINATION ${KF5_INCLUDE_INSTALL_DIR}/KLDAP/KLDAP/
    COMPONENT Devel
)

ecm_generate_pri_file(BASE_NAME Ldap LIB_NAME KF5Ldap DEPS "CoreAddons" FILENAME_VAR PRI_FILENAME INCLUDE_INSTALL_DIR ${KF5_INCLUDE_INSTALL_DIR}/KLDAP/)
install(FILES ${PRI_FILENAME} DESTINATION ${ECM_MKSPECS_INSTALL_DIR})

