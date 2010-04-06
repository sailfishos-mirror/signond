/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
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

#include "signond-common.h"
#include "signonauthsession.h"
#include "signonauthsessionadaptor.h"

namespace SignonDaemonNS {

    SignonAuthSession::SignonAuthSession(quint32 id,
                                         const QString &method) :
                                         m_id(id),
                                         m_method(method)
    {
        TRACE();

        static quint32 incr = 0;
        QString objectName = QLatin1String("/com/nokia/singlesignon/AuthSession_") + QString::number(incr++, 16);
        TRACE() << objectName;

        setObjectName(objectName);
    }

    SignonAuthSession::~SignonAuthSession()
    {
        TRACE();
        //stop all operations from the current session
        QDBusConnection connection(SIGNON_BUS);
        connection.unregisterObject(objectName());
    }

    QString SignonAuthSession::getAuthSessionObjectPath(const quint32 id, const QString &method, SignonDaemon *parent)
    {
        TRACE();
        SignonAuthSession* sas = new SignonAuthSession(id, method);

        QDBusConnection connection(SIGNON_BUS);
        if (!connection.isConnected()) {
            TRACE() << "Cannot get DBUS object connected";
            delete sas;
            return QString();
        }

        (void)new SignonAuthSessionAdaptor(sas);
        QString objectName = sas->objectName();
        if (!connection.registerObject(sas->objectName(), sas, QDBusConnection::ExportAdaptors)) {
            TRACE() << "Object cannot be registered: " << objectName;
            delete sas;
            return QString();
        }

        SignonSessionCore *core = SignonSessionCore::sessionCore(id, method, parent);
        if (!core) {
            TRACE() << "Cannot retrieve proper tasks queue";
            delete sas;
            return QString();
        }

        sas->setParent(core);

        connect(core, SIGNAL(stateChanged(const QString&, int, const QString&)),
                sas, SLOT(stateChangedSlot(const QString&, int, const QString&)));

        TRACE() << "SignonAuthSession is created successfully: " << objectName;
        return objectName;
    }

    void SignonAuthSession::stopAllAuthSessions()
    {
        SignonSessionCore::stopAllAuthSessions();
    }

    quint32 SignonAuthSession::id() const
    {
        return m_id;
    }

    QStringList SignonAuthSession::queryAvailableMechanisms(const QStringList &wantedMechanisms)
    {
        return parent()->queryAvailableMechanisms(wantedMechanisms);
    }

    QVariantMap SignonAuthSession::process(const QVariantMap &sessionDataVa,
                                           const QString &mechanism)
    {
        TRACE();
        setDelayedReply(true);
        parent()->process(connection(),
                          message(),
                          sessionDataVa,
                          mechanism,
                          objectName());
        return QVariantMap();
    }

    void SignonAuthSession::cancel()
    {
        TRACE();
        parent()->cancel(objectName());
    }

    void SignonAuthSession::setId(quint32 id)
    {
        m_id = id;
        parent()->setId(id);
    }

    void SignonAuthSession::objectUnref()
    {
        TRACE();

        cancel();
        delete this;
    }

    void SignonAuthSession::stateChangedSlot(const QString &sessionKey, int state, const QString &message)
    {
        TRACE();

        if (sessionKey == objectName())
            emit stateChanged(state, message);
    }
} //namespace SignonDaemonNS