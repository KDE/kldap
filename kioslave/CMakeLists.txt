# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
add_subdirectory(src)

if (KF${KF_MAJOR_VERSION}DocTools_FOUND)
        add_subdirectory(doc)
endif()

