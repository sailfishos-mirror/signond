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

#include <QObject>

#include "authsession.h"
#include "authsessionimpl.h"
#include <QMetaType>
namespace SignOn {

    AuthSession::AuthSession(quint32 id, const QString &methodName, QObject *parent)
            :  QObject(parent),
               impl(new AuthSessionImpl(this, id, methodName))
    {
        qRegisterMetaType<SessionData>("SessionData");
        qRegisterMetaType<AuthSessionError>("AuthSession::AuthSessionError");
        qRegisterMetaType<AuthSessionState>("AuthSession::AuthSessionState");

        if (qMetaTypeId<SessionData>() < QMetaType::User)
            qCritical() << "AuthSession::AuthSession() - SessionData meta type not registered.";

        if (qMetaTypeId<AuthSessionError>() < QMetaType::User)
            qCritical() << "AuthSession::AuthSession() - AuthSessionError meta type not registered.";

        if (qMetaTypeId<AuthSessionState>() < QMetaType::User)
            qCritical() << "AuthSession::AuthSession() - AuthSessionState meta type not registered.";

    }

    AuthSession::~AuthSession()
    {
        delete impl;
    }

    const QString AuthSession::name() const
    {
        return impl->name();
    }

    void AuthSession::queryAvailableMechanisms(const QStringList &wantedMechanisms)
    {
        impl->queryAvailableMechanisms(wantedMechanisms);
    }

    void AuthSession::process(const SessionData& sessionData, const QString &mechanism)
    {
        impl->process(sessionData, mechanism);
    }

    void AuthSession::cancel()
    {
        impl->cancel();
    }
} //namespace SignOn