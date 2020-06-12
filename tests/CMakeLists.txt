########## next target ###############
set(testldapclient_SRCS testldapclient.cpp)

add_executable(testldapclient ${testldapclient_SRCS})

target_link_libraries(testldapclient KF5::I18n KF5::Completion KF5::Ldap KF5::CoreAddons)


########### next target ###############
#set(testldapsearchdialog_SRCS ldapsearchdialog_gui.cpp)

#add_executable(ldapsearchdialog_gui ${testldapsearchdialog_SRCS})
#target_link_libraries(ldapsearchdialog_gui KF5::Libkdepim KF5::I18n KF5::CoreAddons Qt5::Widgets KF5::Contacts)
