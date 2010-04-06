/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 *
 * Contact: Aurel Popirtac <ext-aurel.popirtac@nokia.com>
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

#ifndef SIGNONDAEMONADAPTER_H_
#define SIGNONDAEMONADAPTER_H_

#include <QtCore>
#include <QtDBus>

#include "signond-common.h"
#include "signondaemon.h"


namespace SignonDaemonNS {

    class SignonDaemonAdaptor: public QDBusAbstractAdaptor
    {
        Q_OBJECT
        Q_CLASSINFO("D-Bus Interface", "com.nokia.singlesignon.SignonDaemon")

    public:
        SignonDaemonAdaptor(SignonDaemon *parent);
        virtual ~SignonDaemonAdaptor();

        inline const QDBusContext &parentDBusContext() const
            { return *static_cast<QDBusContext *>(m_parent); }

    public Q_SLOTS:
        bool initSecureStorage(const QByteArray &lockCode);

        void registerNewIdentity(QDBusObjectPath &objectPath);
        void registerStoredIdentity(const quint32 id, QDBusObjectPath &objectPath, QList<QVariant> &identityData);
        QStringList queryMethods();
        QStringList queryMechanisms(const QString &method);
        QList<QVariant> queryIdentities(const QMap<QString, QVariant> &filter);
        bool clear();
        QString getAuthSessionObjectPath(const quint32 id, const QString &type);

        // Interface method to set the device lock code
        bool setDeviceLockCode(const QByteArray &oldLockCode,
                               const QByteArray &newLockCode);

        // Interface method to set the sim
        bool setSim(const QByteArray &simData,
                    const QByteArray &checkData);

        // Interface method to remote lock the database
        bool remoteLock(const QByteArray &lockCode);

    private:
        void securityErrorReply(const char *failedMethodName);

    private:
        SignonDaemon *m_parent;
    }; //class SignonDaemonAdaptor

} //namespace SignonDaemonNS

#endif /* SIGNONDAEMONADAPTER_H_ */