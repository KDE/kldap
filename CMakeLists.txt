project(kldap)
include(CheckFunctionExists)
include(CheckSymbolExists)

add_definitions( -DKDE_DEFAULT_DEBUG_AREA=5322 )

macro_optional_find_package(Ldap)
macro_log_feature(LDAP_FOUND "OpenLDAP" "LDAP (Lightweight Directory Access Protocol) libraries" "http://www.openldap.org" FALSE "" "Needed to provide LDAP functionality in KDE" )

#look for Sasl2 in the top-level CMakeLists.txt file now
#macro_optional_find_package(Sasl2)
#macro_log_feature(SASL2_FOUND "cyrus-sasl" "Cyrus SASL API" "http://asg.web.cmu.edu/sasl/sasl-library.html" FALSE "" "Needed to support authentication of logins" )

check_include_files(sys/time.h    HAVE_SYS_TIME_H)

set(kldap_EXTRA_LIBS)
set(kldap_EXTRA_INCLUDES)

if (LDAP_FOUND)
   set(kldap_EXTRA_LIBS ${LDAP_LIBRARIES})
   set(kldap_EXTRA_INCLUDES ${LDAP_INCLUDE_DIR})

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


endif (LDAP_FOUND)

if (SASL2_FOUND)
   set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} ${SASL2_LIBRARIES} ${KDE4_KDECORE_LIBS})
   set(kldap_EXTRA_INCLUDES ${kldap_EXTRA_INCLUDES} ${SASL2_INCLUDE_DIR})
endif (SASL2_FOUND)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/kldap_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/kldap_config.h )

add_subdirectory(tests)

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
   ldapattributeproxymodel.cpp)


kde4_add_library(kldap SHARED ${kldap_LIB_SRCS})

include_directories( ${kldap_EXTRA_INCLUDES} )

target_link_libraries(kldap ${KDE4_KIO_LIBS} ${kldap_EXTRA_LIBS} )

set_target_properties(kldap PROPERTIES VERSION ${GENERIC_LIB_VERSION} SOVERSION ${GENERIC_LIB_SOVERSION})
install(TARGETS kldap ${INSTALL_TARGETS_DEFAULT_ARGS})

########### install files ###############

install( FILES ber.h kldap_export.h ldapdefs.h ldif.h ldapurl.h ldapserver.h ldapobject.h
  ldapconnection.h ldapoperation.h
  ldapconfigwidget.h ldapcontrol.h ldapsearch.h
  ldapdn.h ldapmodel.h ldapstructureproxymodel.h ldapattributeproxymodel.h
  DESTINATION ${INCLUDE_INSTALL_DIR}/kldap COMPONENT Devel)
