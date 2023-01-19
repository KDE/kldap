# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
########## next target ###############
add_executable(testldapclient testldapclient.cpp testldapclient.h)

target_link_libraries(testldapclient KF5::I18n KF5::Completion KF5::Ldap KF5::CoreAddons)

#ldapclientsearchconfigreadconfigjobtest.cpp
