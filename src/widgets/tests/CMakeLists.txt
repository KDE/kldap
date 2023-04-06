# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
########## next target ###############
add_executable(testldapclient testldapclient.cpp testldapclient.h)

target_link_libraries(testldapclient KF6::I18n KF6::Completion KPim6::LdapWidgets KPim6::LdapCore KF6::CoreAddons)

