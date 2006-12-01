
if(KDE4_BUILD_TESTS AND LDAP_FOUND)

# Tests don't need to go into toplevel/bin, they are fine in the current dir.
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR} )

include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/.. ${KDE4_KIO_INCLUDES} )

########### next target ###############

set(testkldap_SRCS testkldap.cpp )

kde4_automoc(${testkldap_SRCS})

kde4_add_executable(testkldap RUN_UNINSTALLED ${testkldap_SRCS})

target_link_libraries(testkldap  ${KDE4_KDECORE_LIBS} ${QT_QTTEST_LIBRARY} kldap)

add_test(kldap-testkldap ${EXECUTABLE_OUTPUT_PATH}/testkldap)


endif(KDE4_BUILD_TESTS AND LDAP_FOUND)

