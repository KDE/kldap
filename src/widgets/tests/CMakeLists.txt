# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
########## next target ###############
add_executable(testldapclient testldapclient.cpp testldapclient.h)

target_link_libraries(testldapclient KPim6::LdapWidgets Qt::Widgets)

#####
add_executable(ldapconfigurewidget_gui ldapconfigurewidget_gui.cpp)

target_link_libraries(ldapconfigurewidget_gui KPim6::LdapWidgets Qt::Widgets)
