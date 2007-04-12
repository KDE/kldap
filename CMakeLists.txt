project(kldap)



macro_optional_find_package(Ldap)
macro_log_feature(LDAP_FOUND "OpenLDAP" "LDAP (Lightweight Directory Access Protocol) libraries" "http://www.openldap.org" FALSE "" "Needed to provide LDAP functionality in KDE" )

macro_optional_find_package(Sasl2)
macro_log_feature(SASL2_FOUND "cyrus-sasl" "Cyrus SASL API" "http://asg.web.cmu.edu/sasl/sasl-library.html" FALSE "" "Needed to support authentication of logins" )

check_include_files(sys/time.h    HAVE_SYS_TIME_H)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/kldap_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/kldap_config.h )

set(kldap_EXTRA_LIBS)
set(kldap_EXTRA_INCLUDES)

if (LDAP_FOUND)
set(kldap_EXTRA_LIBS ${LDAP_LIBRARIES} ${LBER_LIBRARIES})
set(klap_EXTRA_INCLUDES ${LDAP_INCLUDE_DIR})
endif (LDAP_FOUND)

if (SASL2_FOUND)
set(kldap_EXTRA_LIBS ${kldap_EXTRA_LIBS} ${SASL2_LIBRARIES} ${KDE4_KDECORE_LIBS})
set(kldap_EXTRA_INCLUDES ${kldap_EXTRA_INCLUDES} ${SASL2_INCLUDE_DIR})
endif (SASL2_FOUND)

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
   ldapmodeltreeitem_p.cpp
   ldapmodel.cpp
   ldapmodel_p.cpp )

kde4_automoc(${kldap_LIB_SRCS})

kde4_add_library(kldap SHARED ${kldap_LIB_SRCS})

include_directories( ${kldap_EXTRA_INCLUDES} )

target_link_libraries(kldap ${KDE4_KIO_LIBS} ${kldap_EXTRA_LIBS} )

set_target_properties(kldap PROPERTIES VERSION ${GENERIC_LIB_VERSION} SOVERSION ${GENERIC_LIB_SOVERSION})
install(TARGETS kldap DESTINATION ${LIB_INSTALL_DIR})


########### install files ###############

install( FILES ber.h kldap.h ldapdefs.h ldif.h ldapurl.h ldapserver.h ldapobject.h 
  ldapconnection.h ldapoperation.h 
  ldapconfigwidget.h ldapcontrol.h ldapsearch.h
  ldapdn.h ldapmodel.h DESTINATION ${INCLUDE_INSTALL_DIR}/kldap)
