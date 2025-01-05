# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
set(PIM_VERSION "6.3.40")

project(KLdap VERSION ${PIM_VERSION})

# ECM setup
set(KF_MIN_VERSION "6.9.0")
set(QT_REQUIRED_VERSION "6.7.0")
set(QT6KEYCHAIN_LIB_VERSION "0.14.2")
find_package(ECM ${KF_MIN_VERSION} CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${KLdap_SOURCE_DIR}/cmake ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)

include(GenerateExportHeader)
include(ECMGenerateHeaders)

include(ECMSetupVersion)
include(KDEGitCommitHooks)
include(KDEClangFormat)
file(GLOB_RECURSE ALL_CLANG_FORMAT_SOURCE_FILES src/*.cpp src/*.h kioworker/*.cpp kioworker/*.h)
kde_clang_format(${ALL_CLANG_FORMAT_SOURCE_FILES})

include(ECMQtDeclareLoggingCategory)
include(ECMDeprecationSettings)
include(ECMFeatureSummary)
include(ECMAddQch)
include(ECMCheckOutboundLicense)
set(KLDAP_LIB_VERSION ${PIM_VERSION})

find_package(KF6KIO ${KF_MIN_VERSION} CONFIG REQUIRED)
find_package(KF6I18n ${KF_MIN_VERSION} CONFIG REQUIRED)
find_package(KF6DocTools ${KF_MIN_VERSION} CONFIG)

find_package(Qt6Keychain ${QT6KEYCHAIN_LIB_VERSION} CONFIG)
set_package_properties(Qt6Keychain PROPERTIES
                                   DESCRIPTION "Provides support for secure credentials storage"
                                   URL "https://github.com/frankosterfeld/qtkeychain"
                                   TYPE REQUIRED)

# tell what is missing without doctools
set_package_properties(KF6DocTools PROPERTIES DESCRIPTION "Provides tools to generate documentation in various format from DocBook files"
                       TYPE OPTIONAL
                       PURPOSE "Required to build documentation")

option(BUILD_QCH "Build API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)" OFF)
add_feature_info(QCH ${BUILD_QCH} "API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)")


option(USE_UNITY_CMAKE_SUPPORT "Use UNITY cmake support (speedup compile time)" OFF)
set(COMPILE_WITH_UNITY_CMAKE_SUPPORT OFF)
if(USE_UNITY_CMAKE_SUPPORT)
    set(COMPILE_WITH_UNITY_CMAKE_SUPPORT ON)
endif()

########### Find packages ###########
find_package(KF6WidgetsAddons ${KF_MIN_VERSION} CONFIG REQUIRED)

add_definitions(-DQT_NO_CONTEXTLESS_CONNECT)
# -fhardened increase compilation time and produce a lot of warning
option(OPTION_DISABLE_HARDENED_OPTIMIZATION "Disable -fhardened" OFF)
if(OPTION_DISABLE_HARDENED_OPTIMIZATION)
   string(REPLACE "-fhardened" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
   string(REPLACE "-fhardened" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()
ecm_set_disabled_deprecation_versions(QT 6.8.1 KF 6.10.0)


find_package(Ldap)
set_package_properties(Ldap PROPERTIES
  TYPE RECOMMENDED
  PURPOSE "Needed to provide LDAP functionality in KDE"
)

find_package(Sasl2)
set_package_properties(Sasl2 PROPERTIES TYPE REQUIRED)

if(Ldap_FOUND)
   set(LDAP_FOUND 1)
endif()

add_definitions(-DTRANSLATION_DOMAIN=\"libkldap6\")


########### Targets ###########
add_subdirectory(src)
add_subdirectory(kioworker)

ecm_qt_install_logging_categories(
        EXPORT KLDAP
        FILE kldap.categories
        DESTINATION ${KDE_INSTALL_LOGGINGCATEGORIESDIR}
       )

kde_configure_git_pre_commit_hook(CHECKS CLANG_FORMAT)
ki18n_install(po)
if(KF6DocTools_FOUND)
   kdoctools_install(po)
endif()
ecm_feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
file(GLOB_RECURSE ALL_SOURCE_FILES src/*.cpp src/*.h kioworker/*.cpp kioworker/*.h)
ecm_check_outbound_license(LICENSES GPL-2.0-only  FILES ${ALL_SOURCE_FILES})
