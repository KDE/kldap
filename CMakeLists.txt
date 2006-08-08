project(kldap)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/kldap_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/kldap_config.h )

add_subdirectory(tests)
########### next target ###############


set(kldap_LIB_SRCS 
   ldif.cpp 
   ldapurl.cpp
   ldapserver.cpp
   ldapobject.cpp
   ldapconnection.cpp
   ldapoperation.cpp
   ldapcontrol.cpp
   ldapconfigwidget.cpp )

kde4_automoc(${kldap_LIB_SRCS})

kde4_add_library(kldap SHARED ${kldap_LIB_SRCS})

include_directories( ${SASL2_INCLUDE_DIR} ${LDAP_INCLUDE_DIR} )

target_link_libraries(kldap  ${KDE4_KIO_LIBS} ${LDAP_LIBRARIES} ${LBER_LIBRARIES} )

set_target_properties(kldap PROPERTIES VERSION ${GENERIC_LIB_VERSION} SOVERSION ${GENERIC_LIB_SOVERSION})
install(TARGETS kldap DESTINATION ${LIB_INSTALL_DIR})


########### install files ###############

install( FILES kldap.h ldapdefs.h ldif.h ldapurl.h ldapserver.h ldapobject.h 
  ldapconnection.h ldapoperation.h 
  ldapconfigwidget.h ldapcontrol.h DESTINATION ${INCLUDE_INSTALL_DIR}/kldap)
