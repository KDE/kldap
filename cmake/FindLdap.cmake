# - Try to find the LDAP client libraries
# Once done this will define
#
#  Ldap_FOUND - system has libldap
#  Ldap_INCLUDE_DIRS - the ldap include directory
#  Ldap_LIBRARIES - libldap + liblber (if found) library


find_path(Ldap_INCLUDE_DIRS ldap.h)

if(APPLE)
   find_library(Ldap_LIBRARIES NAMES LDAP
      PATHS
      /System/Library/Frameworks
      /Library/Frameworks
   )
else()
   find_library(Ldap_LIBRARIES NAMES ldap)
   find_library(Lber_LIBRARIES NAMES lber)
endif()

if(Ldap_LIBRARIES AND Lber_LIBRARIES)
  set(Ldap_LIBRARIES ${Ldap_LIBRARIES} ${Lber_LIBRARIES})
endif()

if(EXISTS ${Ldap_INCLUDE_DIRS}/ldap_features.h)
  file(READ ${Ldap_INCLUDE_DIRS}/ldap_features.h LDAP_FEATURES_H_CONTENT)
  string(REGEX MATCH "#define LDAP_VENDOR_VERSION_MAJOR[ ]+[0-9]+" _LDAP_VERSION_MAJOR_MATCH ${LDAP_FEATURES_H_CONTENT})
  string(REGEX MATCH "#define LDAP_VENDOR_VERSION_MINOR[ ]+[0-9]+" _LDAP_VERSION_MINOR_MATCH ${LDAP_FEATURES_H_CONTENT})
  string(REGEX MATCH "#define LDAP_VENDOR_VERSION_PATCH[ ]+[0-9]+" _LDAP_VERSION_PATCH_MATCH ${LDAP_FEATURES_H_CONTENT})

  string(REGEX REPLACE ".*_MAJOR[ ]+(.*)" "\\1" LDAP_VERSION_MAJOR ${_LDAP_VERSION_MAJOR_MATCH})
  string(REGEX REPLACE ".*_MINOR[ ]+(.*)" "\\1" LDAP_VERSION_MINOR ${_LDAP_VERSION_MINOR_MATCH})
  string(REGEX REPLACE ".*_PATCH[ ]+(.*)" "\\1" LDAP_VERSION_PATCH ${_LDAP_VERSION_PATCH_MATCH})

  set(Ldap_VERSION "${LDAP_VERSION_MAJOR}.${LDAP_VERSION_MINOR}.${LDAP_VERSION_PATCH}")
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Ldap
    FOUND_VAR Ldap_FOUND
    REQUIRED_VARS Ldap_LIBRARIES Ldap_INCLUDE_DIRS
    VERSION_VAR Ldap_VERSION
)

mark_as_advanced(Ldap_INCLUDE_DIRS Ldap_LIBRARIES Lber_LIBRARIES Ldap_VERSION)
