/*
 * This file is part of signon
 *
 * Copyright (C) 2011 Nokia Corporation.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "misc.h"

extern "C" {
    #include <sys/stat.h>
}

#include <QDir>

namespace SignonDaemonNS {

bool setUserOwnership(const QString &filePath)
{
    const char *userHomePath = QDir::homePath().toLatin1().data();
    struct stat fileInfo;
    if (stat(userHomePath, &fileInfo) != 0)
        return false;

    const char *filePathStr = filePath.toLatin1().data();
    if (chown(filePathStr, fileInfo.st_uid , fileInfo.st_gid) != 0)
        return false;

    return true;
}

bool setFilePermissions(const QString &filePath,
                        const QFile::Permissions desiredPermissions,
                        bool keepExisting)
{
    if (!QFile::exists(filePath)) return false;

    QFile::Permissions newPermissions = desiredPermissions;

    QFile file(filePath);
    QFile::Permissions initialPermissions = file.permissions();

    if (keepExisting)
        newPermissions |= initialPermissions;

    if (newPermissions != initialPermissions)
        return file.setPermissions(newPermissions);

    return true;
}

} //SignonDaemonNS