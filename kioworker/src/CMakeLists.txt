# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
add_library(kio_ldap MODULE)
target_sources(kio_ldap PRIVATE kio_ldap.cpp kio_ldap.h)
ecm_qt_declare_logging_category(kio_ldap
        HEADER kldap_debug.h
        IDENTIFIER KLDAP_KIO_WORKERS_LOG
        CATEGORY_NAME kf.kio.workers.ldap
        DESCRIPTION "ldap KIO worker"
        OLD_CATEGORY_NAMES log_kldap org.kde.pim.kldap
        EXPORT KLDAP
)


target_link_libraries(kio_ldap Qt::Network KF6::KIOCore KF6::I18n KPim6::LdapCore)
if(WIN32)
    target_link_libraries(kio_ldap ws2_32)
endif()
set_target_properties(kio_ldap PROPERTIES OUTPUT_NAME "ldap")
install(TARGETS kio_ldap  DESTINATION ${KDE_INSTALL_PLUGINDIR}/kf6/kio)
