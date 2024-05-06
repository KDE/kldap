/*
    SPDX-FileCopyrightText: 2024 Laurent Montel <montel.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <KLDAPWidgets/LdapConfigureWidget>
#include <QApplication>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("ldapconfigurewidget_gui"));
    auto t = new KLDAPWidgets::LdapConfigureWidget();
    t->load();
    t->show();
    app.exec();
    delete t;
}
