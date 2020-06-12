########## next target ###############
set(testldapclient_SRCS testldapclient.cpp)

add_executable(testldapclient ${testldapclient_SRCS})

target_link_libraries(testldapclient KF5::I18n KF5::Completion KF5::Ldap KF5::CoreAddons)
