
set(kio_ldap_PART_SRCS kio_ldap.cpp)
ecm_qt_declare_logging_category(kio_ldap_PART_SRCS HEADER kldap_debug.h IDENTIFIER KLDAP_LOG CATEGORY_NAME log_kldap)

add_library(kio_ldap MODULE ${kio_ldap_PART_SRCS})

target_link_libraries(kio_ldap KF5::KIOCore KF5::I18n KF5::Ldap KF5::Mbox)
set_target_properties(kio_ldap PROPERTIES OUTPUT_NAME "ldap")
install(TARGETS kio_ldap  DESTINATION ${KDE_INSTALL_PLUGINDIR}/kf5/kio)


########### install files ###############

install( FILES ldap.protocol ldaps.protocol  DESTINATION  ${KDE_INSTALL_KSERVICES5DIR} )
