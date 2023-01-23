# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
########## next target ###############
add_executable(testldapclient testldapclient.cpp testldapclient.h)

target_link_libraries(testldapclient KF${KF_MAJOR_VERSION}::I18n KF${KF_MAJOR_VERSION}::Completion KF5::Ldap KF${KF_MAJOR_VERSION}::CoreAddons)

#ldapclientsearchconfigreadconfigjobtest.cpp
