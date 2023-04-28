# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
include(ECMAddTests)

find_package(Qt6Test CONFIG REQUIRED)

add_executable(ldapclientsearchconfigreadconfigjobtest ldapclientsearchconfigreadconfigjobtest.cpp ldapclientsearchconfigreadconfigjobtest.h)
add_test(NAME ldapclientsearchconfigreadconfigjobtest COMMAND ldapclientsearchconfigreadconfigjobtest)
ecm_mark_as_test(ldapclientsearchconfigreadconfigjobtest)
target_link_libraries(ldapclientsearchconfigreadconfigjobtest Qt::Test KPim6::LdapWidgets KPim6::LdapCore KF6::ConfigCore)

