# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause

ecm_setup_version(PROJECT VARIABLE_PREFIX KLDAPWIDGETS
    VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kldap_widgets_version.h"
    PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapWidgetsConfigVersion.cmake"
    SOVERSION 6
)

add_library(KPim6LdapWidgets)
add_library(KPim6::LdapWidgets ALIAS KPim6LdapWidgets)

target_sources(
    KPim6LdapWidgets
    PRIVATE
        ldapconfigwidget.cpp
        addhostdialog.cpp
        ldapconfigurewidgetng.cpp
        addhostdialog.h
        ldapconfigwidget.h
        ldapconfigurewidgetng.h
        ldapconfigurewidgetng.cpp
        ldapconfigurewidgetng.h
        ldapactivitiesabstractplugin.h
        ldapactivitiesabstractplugin.cpp
)

ecm_qt_declare_logging_category(KPim6LdapWidgets HEADER ldap_widgets_debug.h IDENTIFIER LDAP_LOG CATEGORY_NAME org.kde.pim.ldap.widgets
    DESCRIPTION "kldap widgets (kldap)"
    OLD_CATEGORY_NAMES log_ldap_widgets
    EXPORT KLDAP
)

ecm_qt_declare_logging_category(KPim6LdapWidgets HEADER ldapclient_debug.h IDENTIFIER LDAPCLIENT_LOG CATEGORY_NAME org.kde.pim.ldapclient
    DESCRIPTION "ldapclient (kldap)"
    OLD_CATEGORY_NAMES log_ldapclient
    EXPORT KLDAP
)

if(COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(
        KPim6LdapWidgets
        PROPERTIES
            UNITY_BUILD
                ON
    )
endif()
generate_export_header(KPim6LdapWidgets BASE_NAME kldapwidgets)

target_link_libraries(
    KPim6LdapWidgets
    PUBLIC
        KPim6::LdapCore
    PRIVATE
        Qt::Widgets
        KF6::I18n
        KF6::WidgetsAddons
        KF6::ConfigCore
        KF6::CoreAddons
        KF6::KIOCore
        KF6::ConfigGui
)

target_link_libraries(KPim6LdapWidgets PRIVATE qt6keychain)

target_include_directories(
    KPim6LdapWidgets
    INTERFACE
        "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPWidgets>"
)
target_include_directories(
    KPim6LdapWidgets
    PUBLIC
        "$<BUILD_INTERFACE:${KLdap_SOURCE_DIR}/src/widgets;${KLdap_BINARY_DIR}/src>"
)

set_target_properties(
    KPim6LdapWidgets
    PROPERTIES
        VERSION
            ${KLDAPWIDGETS_VERSION}
        SOVERSION
            ${KLDAPWIDGETS_SOVERSION}
        EXPORT_NAME
            LdapWidgets
)

install(TARGETS KPim6LdapWidgets EXPORT KPim6LdapWidgetsTargets ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})

########### install files ###############

ecm_generate_headers(KLdapWidgets_CamelCase_HEADERS
    HEADER_NAMES
    LdapConfigWidget
    AddHostDialog
    LdapConfigureWidgetNg
    LdapActivitiesAbstractPlugin
    PREFIX KLDAPWidgets
    REQUIRED_HEADERS KLdapWidgets_HEADERS
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/kldapwidgets_export.h
        ${KLdapWidgets_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPWidgets/kldapwidgets
    COMPONENT Devel
)

install(
    FILES
        ${KLdapWidgets_CamelCase_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPWidgets/KLDAPWidgets/
    COMPONENT Devel
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/kldap_widgets_version.h
    DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/KLDAPWidgets
    COMPONENT Devel
)

if(BUILD_QCH)
    ecm_add_qch(
        KPim6LdapWidgets_QCH
        NAME KLdapWidgets
        BASE_NAME KPim6LdapWidgets
        VERSION ${PIM_VERSION}
        ORG_DOMAIN org.kde

        SOURCES # using only public headers, to cover only public API
        ${KLdapWidgets_HEADERS}
        MD_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md"
        #IMAGE_DIRS "${CMAKE_SOURCE_DIR}/docs/pics"
        LINK_QCHS
        Qt6Core_QCH
        Qt6Gui_QCH
        Qt6Widgets_QCH
        INCLUDE_DIRS
        ${CMAKE_CURRENT_BINARY_DIR}
        BLANK_MACROS
        KLDAPWIDGETS_EXPORT
        TAGFILE_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        QCH_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        COMPONENT Devel
    )
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
    add_subdirectory(autotests)
endif()

set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KPim6LdapWidgets")

install(
    EXPORT KPim6LdapWidgetsTargets
    DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
    FILE KPim6LdapWidgetsTargets.cmake
    NAMESPACE KPim6::
)

if(BUILD_QCH)
    ecm_install_qch_export(
        TARGETS KPim6LdapWidgets_QCH
        FILE KPim6LdapWidgetsQchTargets.cmake
        DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
        COMPONENT Devel
    )
    set(PACKAGE_INCLUDE_QCHTARGETS "include(\"\${CMAKE_CURRENT_LIST_DIR}/KPim6LdapWidgetsQchTargets.cmake\")")
endif()

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/KPimLdapWidgetsConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapWidgetsConfig.cmake"
    INSTALL_DESTINATION ${CMAKECONFIG_INSTALL_DIR}
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapWidgetsConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/KPim6LdapWidgetsConfigVersion.cmake"
    DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
    COMPONENT Devel
)
