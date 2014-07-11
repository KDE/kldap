include(ECMAddTests)

find_package(Qt5Test CONFIG REQUIRED)

if(Ldap_FOUND)
  ecm_add_tests(testkldap.cpp NAME_PREFIX "kldap-" LINK_LIBRARIES KF5::Ldap Qt5::Test)
endif()
