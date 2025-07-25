/*
    SPDX-FileCopyrightText: 2024-2025 Laurent Montel <montel@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <KLDAPWidgets/LdapConfigureWidgetNg>
#include <QApplication>
using namespace Qt::Literals::StringLiterals;
int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    app.setApplicationName(u"ldapconfigurewidgetng_gui"_s);
    auto t = new KLDAPWidgets::LdapConfigureWidgetNg();
    t->load();
    t->show();
    app.exec();
    t->save();
    delete t;
}
