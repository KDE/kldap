project(kldap)
include(CheckFunctionExists)
include(CheckSymbolExists)

add_definitions(-DKDE_DEFAULT_DEBUG_AREA=5322)
add_definitions( -DQT_NO_CAST_FROM_ASCII )
add_definitions( -DQT_NO_CAST_TO_ASCII )


find_package(Ldap)
if(NOT WINCE) #FIXME enable for win32
  set_package_properties(Ldap PROPERTIES DESCRIPTION "LDAP (Lightweight Directory Access Protocol) libraries" URL "http://www.openldap.org" TYPE RECOMMENDED PURPOSE "Needed to provide LDAP functionality in KDE")
else()
  set_package_properties(Ldap PROPERTIES DESCRIPTION "LDAP (Lightweight Directory Access Protocol) libraries" URL "http://www.openldap.org" TYPE OPTIONAL PURPOSE "Needed to provide LDAP functionality in KDE")
endif()

check_include_files(sys/time.h HAVE_SYS_TIME_H)

set(kldap_EXTRA_LIBS)
set(kldap_EXTRA_INCLUDES)

if(LDAP_FOUND)
  set(kldap_EXTRA_LIBS ${LDAP_LIBRARIES})
  set(kldap_EXTRA_INCLUDES ${LDAP_INCLUDE_DIR})
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
else()
  if(WINCE)
    set(LDAP_FOUND TRUE)
    set(HAVE_WINLDAP_H TRUE)
    set(CMAKE_REQUIRED_INCLUDES winldap.h w32-ldap-help.h)
    set(CMAKE_REQUIRED_LIBRARIES wldap32)
    set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} wldap32)
    # Checks left in for compatibility
    check_function_exists(ldap_start_tls_s HAVE_LDAP_START_TLS_S)
    check_function_exists(ldap_initialize HAVE_LDAP_INITIALIZE)
    check_function_exists(ber_memfree HAVE_BER_MEMFREE)
    check_function_exists(ldap_unbind_ext HAVE_LDAP_UNBIND_EXT)
    check_function_exists(ldap_extended_operation HAVE_LDAP_EXTENDED_OPERATION)
    check_function_exists(ldap_extended_operation_s HAVE_LDAP_EXTENDED_OPERATION_S)
    check_symbol_exists(ldap_extended_operation winldap.h HAVE_LDAP_EXTENDED_OPERATION_PROTOTYPE)
    check_symbol_exists(ldap_extended_operation_s winldap.h HAVE_LDAP_EXTENDED_OPERATION_S_PROTOTYPE)
  endif()
endif()

if(SASL2_FOUND)
  set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} ${SASL2_LIBRARIES})
  set(kldap_EXTRA_INCLUDES ${kldap_EXTRA_INCLUDES} ${SASL2_INCLUDE_DIR})
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/kldap_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/kldap_config.h)

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
  ldapattributeproxymodel.cpp
)

add_library(kldap ${LIBRARY_TYPE} ${kldap_LIB_SRCS})
generate_export_header(kldap)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${Boost_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/kabc
  ${kldap_EXTRA_INCLUDES}
)

# TODO KF5: we only need KDEUI here, remove KCM, KIO and KABC
target_link_libraries(kldap
  ${KDE4_KIO_LIBS}
  ${KDE4_KCMUTILS_LIBS}
  ${KDE4_KDECORE_LIBS}
  ${kldap_EXTRA_LIBS}
  kabc
)

set_target_properties(kldap PROPERTIES
  VERSION ${GENERIC_LIB_VERSION}
  SOVERSION ${GENERIC_LIB_SOVERSION}
)
install(TARGETS kldap EXPORT kdepimlibsLibraryTargets ${INSTALL_TARGETS_DEFAULT_ARGS})

########### install files ###############

install(FILES
  ber.h
  ${CMAKE_CURRENT_BINARY_DIR}/kldap_export.h
  ldapattributeproxymodel.h
  ldapconfigwidget.h
  ldapconnection.h
  ldapcontrol.h
  ldapdefs.h
  ldapdn.h
  ldapmodel.h
  ldapobject.h
  ldapoperation.h
  ldapsearch.h
  ldapserver.h
  ldapstructureproxymodel.h
  ldapurl.h
  ldif.h
  DESTINATION ${INCLUDE_INSTALL_DIR}/kldap COMPONENT Devel
)
