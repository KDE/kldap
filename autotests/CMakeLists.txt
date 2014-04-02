include(ECMMarkAsTest)

find_package(Qt5Test CONFIG REQUIRED)

if(LDAP_FOUND)

########### next target ###############

  set(testkldap_SRCS testkldap.cpp)
  add_executable(testkldap ${testkldap_SRCS})
  add_test(testkldap testkldap)
  ecm_mark_as_test(testkldap)
  target_link_libraries(testkldap KF5KLdap Qt5::Test)
endif()
