add_library(kio_ldap MODULE)

target_sources(kio_ldap PRIVATE kio_ldap.cpp)
ecm_qt_declare_logging_category(kio_ldap HEADER kldap_debug.h IDENTIFIER KLDAP_LOG CATEGORY_NAME org.kde.pim.kldap
        DESCRIPTION "kioslave (kldap)"
        OLD_CATEGORY_NAMES log_kldap
        EXPORT KLDAP
    )


target_link_libraries(kio_ldap Qt::Network KF5::KIOCore KF5::I18n KF5::Ldap)
if (WIN32)
    target_link_libraries(kio_ldap ws2_32)
endif()
set_target_properties(kio_ldap PROPERTIES OUTPUT_NAME "ldap")
install(TARGETS kio_ldap  DESTINATION ${KDE_INSTALL_PLUGINDIR}/kf5/kio)
