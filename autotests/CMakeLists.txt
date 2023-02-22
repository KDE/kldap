# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
include(ECMAddTests)

find_package(Qt${QT_MAJOR_VERSION}Test CONFIG REQUIRED)

if(Ldap_FOUND)
  ecm_add_tests(testkldap.cpp NAME_PREFIX "kldap-" LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Ldap Qt::Test)
endif()

add_executable(ldapclientsearchconfigreadconfigjobtest ldapclientsearchconfigreadconfigjobtest.cpp)
add_test(NAME ldapclientsearchconfigreadconfigjobtest COMMAND ldapclientsearchconfigreadconfigjobtest)
ecm_mark_as_test(ldapclientsearchconfigreadconfigjobtest)
target_link_libraries(ldapclientsearchconfigreadconfigjobtest Qt::Test KPim${KF_MAJOR_VERSION}::Ldap KF${KF_MAJOR_VERSION}::ConfigCore)

