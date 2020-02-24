
set(kio_ldap_PART_SRCS kio_ldap.cpp)
if (ECM_VERSION VERSION_LESS "5.68.0")
    ecm_qt_declare_logging_category(kio_ldap_PART_SRCS HEADER kldap_debug.h IDENTIFIER KLDAP_LOG CATEGORY_NAME org.kde.pim.kldap)
else()
    ecm_qt_declare_logging_category(kio_ldap_PART_SRCS HEADER kldap_debug.h IDENTIFIER KLDAP_LOG CATEGORY_NAME org.kde.pim.kldap
        DESCRIPTION "kioslave (kldap)"
        OLD_CATEGORY_NAMES log_kldap
        EXPORT KLDAP
    )
endif()

add_library(kio_ldap MODULE ${kio_ldap_PART_SRCS})

target_link_libraries(kio_ldap Qt5::Network KF5::KIOCore KF5::I18n KF5::Ldap)
if (WIN32)
    target_link_libraries(kio_ldap ws2_32)
endif()
set_target_properties(kio_ldap PROPERTIES OUTPUT_NAME "ldap")
install(TARGETS kio_ldap  DESTINATION ${KDE_INSTALL_PLUGINDIR}/kf5/kio)


########### install files ###############

install( FILES ldap.protocol ldaps.protocol  DESTINATION  ${KDE_INSTALL_KSERVICES5DIR} )
