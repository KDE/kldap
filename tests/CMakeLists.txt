

if(LDAP_FOUND)
set( EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )
include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/.. ${KDE4_KIO_INCLUDES} )

########### next target ###############

set(testkldap_SRCS testkldap.cpp )


kde4_add_unit_test(testkldap TESTNAME kldap-testkldap ${testkldap_SRCS})

target_link_libraries(testkldap  ${KDE4_KDECORE_LIBS} ${QT_QTTEST_LIBRARY} kldap)


endif(LDAP_FOUND)

