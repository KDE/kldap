include(ECMAddTests)

find_package(Qt5Test CONFIG REQUIRED)

if(Ldap_FOUND)
  ecm_add_tests(testkldap.cpp NAME_PREFIX "kldap-" LINK_LIBRARIES KF5::Ldap Qt5::Test)
endif()

set(ldapclientsearchconfigreadconfigjobtest_source ldapclientsearchconfigreadconfigjobtest.cpp)
add_executable(ldapclientsearchconfigreadconfigjobtest ${ldapclientsearchconfigreadconfigjobtest_source})
add_test(NAME ldapclientsearchconfigreadconfigjobtest COMMAND ldapclientsearchconfigreadconfigjobtest)
ecm_mark_as_test(ldapclientsearchconfigreadconfigjobtest)
target_link_libraries(ldapclientsearchconfigreadconfigjobtest Qt5::Test KF5::Ldap) 

