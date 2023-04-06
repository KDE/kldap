# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
include(ECMAddTests)

find_package(Qt6Test CONFIG REQUIRED)

if(Ldap_FOUND)
  ecm_add_tests(testkldap.cpp NAME_PREFIX "kldap-" LINK_LIBRARIES KPim6::LdapCore Qt::Test)
endif()
