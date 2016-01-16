cmake_minimum_required(VERSION 2.8.12)

project(KLdap)

# ECM setup
find_package(ECM 5.17.0 CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${KLdap_SOURCE_DIR}/cmake ${ECM_MODULE_PATH})

include(GenerateExportHeader)
include(ECMGenerateHeaders)
include(ECMGeneratePriFile)
include(ECMPackageConfigHelpers)
include(ECMSetupVersion)
include(FeatureSummary)
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDEFrameworkCompilerSettings)
include(ECMQtDeclareLoggingCategory)

set(KF5_VERSION "5.17.0")
set(KLDAP_LIB_VERSION "5.1.40")

ecm_setup_version(${KLDAP_LIB_VERSION} VARIABLE_PREFIX KLDAP
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kldap_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5LdapConfigVersion.cmake"
                        SOVERSION 5
)

########### Find packages ###########
find_package(KF5Completion ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5WidgetsAddons ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5I18n ${KF5_VERSION} CONFIG REQUIRED)


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
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KF5Ldap")

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
   DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF5}
   COMPONENT Devel
)

########### Targets ###########
add_subdirectory(cmake)
add_subdirectory(src)

if(BUILD_TESTING)
    add_subdirectory(autotests)
endif()

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
