include(ECMAddTests)

find_package(Qt5Test CONFIG REQUIRED)

if(Ldap_FOUND)

########### next target ###############
  ecm_add_tests(testkldap.cpp NAME_PREFIX "kldap-" LINK_LIBRARIES KF5Ldap Qt5::Test)
endif()
