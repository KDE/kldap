cmake_minimum_required(VERSION 2.8.12)

project(KLdap)

# ECM setup
find_package(ECM 0.0.11 CONFIG REQUIRED)
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


# FIXME: Do we want the same versions in kdepimlibs and kf5?
set(KF5_VERSION "4.97.0")

ecm_setup_version(${KF5_VERSION} VARIABLE_PREFIX KLDAP
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kldap_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5KLdapConfigVersion.cmake"
                        SOVERSION 5
)

########### Find packages ###########
find_package(KF5KIO ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5KCMUtils ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5KDE4Support ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5Abc ${KF5_VERSION} CONFIG REQUIRED)

add_definitions(-DKDE_DEFAULT_DEBUG_AREA=5322)

add_subdirectory(src)
add_subdirectory(tests)
