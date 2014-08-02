cmake_minimum_required(VERSION 2.8.12)

project(kldap)

# ECM setup
find_package(ECM 1.1.0 CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${kldap_SOURCE_DIR}/cmake ${ECM_MODULE_PATH})

include(GenerateExportHeader)
include(ECMGenerateHeaders)
include(ECMGeneratePriFile)
include(ECMPackageConfigHelpers)
include(ECMSetupVersion)
include(FeatureSummary)
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDEFrameworkCompilerSettings)


# FIXME: Do we want the same versions in kdepimlibs and kf5?
set(KF5_VERSION "5.1.0")
set(KDEPIMLIBS_VERSION "4.70.0")

ecm_setup_version(${KDEPIMLIBS_VERSION} VARIABLE_PREFIX KLDAP
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kldap_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5LdapConfigVersion.cmake"
                        SOVERSION 5
)

########### Find packages ###########
find_package(KF5KIO ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5KCMUtils ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5KDELibs4Support ${KF5_VERSION} CONFIG REQUIRED)

if(${CMAKE_SOURCE_DIR} STREQUAL ${kldap_SOURCE_DIR})
  find_package(KF5Abc ${KDEPIMLIBS_VERSION} CONFIG REQUIRED)
endif()


find_package(Ldap)
set_package_properties(Ldap PROPERTIES
  DESCRIPTION "LDAP (Lightweight Directory Access Protocol) libraries"
  URL "http://www.openldap.org"
  TYPE RECOMMENDED
  PURPOSE "Needed to provide LDAP functionality in KDE"
)

find_package(Sasl2)
set_package_properties(Sasl2 PROPERTIES
                             DESCRIPTION "The Cyrus-sasl library"
                             URL "http://www.cyrussasl.org"
                             TYPE OPTIONAL
)

if (Ldap_FOUND)
   set(LDAP_FOUND 1)
endif()

if (Sasl2_FOUND)
   set(SASL2_FOUND 1)
endif()

add_definitions("-DQT_NO_CAST_FROM_ASCII -DQT_NO_CAST_TO_ASCII")
add_definitions(-DTRANSLATION_DOMAIN=\"libkldap5\")

########### CMake Config Files ###########
set(CMAKECONFIG_INSTALL_DIR "${CMAKECONFIG_INSTALL_PREFIX}/KF5Ldap")

ecm_configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/KF5LdapConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/KF5LdapConfig.cmake"
  INSTALL_DESTINATION  ${CMAKECONFIG_INSTALL_DIR}
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/KF5LdapConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/KF5LdapConfigVersion.cmake"
  DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
  COMPONENT Devel
)

install(EXPORT KF5LdapTargets DESTINATION "${CMAKECONFIG_INSTALL_DIR}" FILE KF5LdapTargets.cmake NAMESPACE KF5::)

install(FILES
   ${CMAKE_CURRENT_BINARY_DIR}/kldap_version.h
   DESTINATION ${KF5_INCLUDE_INSTALL_DIR}
   COMPONENT Devel
)

########### Targets ###########
add_subdirectory(cmake)
add_subdirectory(src)
add_subdirectory(autotests)

if ("${CMAKE_BINARY_DIR}" STREQUAL "${kldap_BINARY_DIR}")
  feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
endif()
