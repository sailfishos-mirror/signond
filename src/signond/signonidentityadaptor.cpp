/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2011 Intel Corporation.
 * Copyright (C) 2013-2016 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
 * Contact: Jussi Laako <jussi.laako@linux.intel.com>
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

#include "signonidentityadaptor.h"

#include "erroradaptor.h"
#include "signonidentity.h"
#include "accesscontrolmanagerhelper.h"

namespace SignonDaemonNS {

SignonIdentityAdaptor::SignonIdentityAdaptor(SignonIdentity *parent):
    QDBusAbstractAdaptor(parent),
    m_parent(parent)
{
    setAutoRelaySignals(true);
}

SignonIdentityAdaptor::~SignonIdentityAdaptor()
{
}

void SignonIdentityAdaptor::securityErrorReply(const char *failedMethodName)
{
    QString errMsg;
    QTextStream(&errMsg) << SIGNOND_PERMISSION_DENIED_ERR_STR
                         << "Method:"
                         << failedMethodName;

    errorReply(SIGNOND_PERMISSION_DENIED_ERR_NAME, errMsg);
    TRACE() << "Method FAILED Access Control check:" << failedMethodName;
}

void SignonIdentityAdaptor::errorReply(const QString &name,
                                       const QString &message)
{
    QDBusMessage msg = parentDBusContext().message();
    msg.setDelayedReply(true);
    QDBusMessage errReply = msg.createErrorReply(name, message);
    parentDBusContext().connection().send(errReply);
}

quint32 SignonIdentityAdaptor::requestCredentialsUpdate(const QString &msg)
{
    const QDBusContext &context = parentDBusContext();
    QDBusConnection connection = context.connection();
    const QDBusMessage &message = context.message();

    /* Access Control */
    if (!AccessControlManagerHelper::instance()->isPeerAllowedToUseIdentity(
                                    connection,
                                    message,
                                    m_parent->id())) {
        securityErrorReply(__func__);
        return 0;
    }

    auto callback = [=](quint32 ret, const Error &error) {
        if (!error) {
            QDBusMessage dbusreply = message.createReply();
            dbusreply << ret;
            connection.send(dbusreply);
        } else {
            connection.send(ErrorAdaptor(error).createReply(message));
        }
    };
    m_parent->requestCredentialsUpdate(msg, callback);
    context.setDelayedReply(true);
    return 0; // ignored
}

QVariantMap SignonIdentityAdaptor::getInfo()
{
    const QDBusContext &context = parentDBusContext();
    QDBusConnection connection = context.connection();
    const QDBusMessage &message = context.message();

    /* Access Control */
    if (!AccessControlManagerHelper::instance()->isPeerAllowedToUseIdentity(
                                    connection,
                                    message,
                                    m_parent->id())) {
        securityErrorReply(__func__);
        return QVariantMap();
    }

    SignonIdentityInfo info;
    Error error = m_parent->getInfo(&info);
    if (error) {
        connection.send(ErrorAdaptor(error).createReply(message));
    }
    return info.toMap();
}

void SignonIdentityAdaptor::addReference(const QString &reference)
{
    const QDBusConnection &connection = parentDBusContext().connection();
    const QDBusMessage &message = parentDBusContext().message();

    /* Access Control */
    if (!AccessControlManagerHelper::instance()->isPeerAllowedToUseIdentity(
                                    connection,
                                    message,
                                    m_parent->id())) {
        securityErrorReply(__func__);
        return;
    }

    QString appId =
        AccessControlManagerHelper::instance()->appIdOfPeer(connection,
                                                            message);
    Error error = m_parent->addReference(reference, appId);
    if (error) {
        connection.send(ErrorAdaptor(error).createReply(message));
    }
}

void SignonIdentityAdaptor::removeReference(const QString &reference)
{
    const QDBusConnection &connection = parentDBusContext().connection();
    const QDBusMessage &message = parentDBusContext().message();

    /* Access Control */
    if (!AccessControlManagerHelper::instance()->isPeerAllowedToUseIdentity(
                                    connection,
                                    message,
                                    m_parent->id())) {
        securityErrorReply(__func__);
        return;
    }

    QString appId =
        AccessControlManagerHelper::instance()->appIdOfPeer(connection,
                                                            message);
    Error error = m_parent->removeReference(reference, appId);
    if (error) {
        connection.send(ErrorAdaptor(error).createReply(message));
    }
}


bool SignonIdentityAdaptor::verifyUser(const QVariantMap &params)
{
    const QDBusContext &context = parentDBusContext();
    QDBusConnection connection = context.connection();
    const QDBusMessage &message = context.message();

    /* Access Control */
    if (!AccessControlManagerHelper::instance()->isPeerAllowedToUseIdentity(
                                    connection,
                                    message,
                                    m_parent->id())) {
        securityErrorReply(__func__);
        return false;
    }

    auto callback = [=](bool ret, const Error &error) {
        if (!error) {
            QDBusMessage dbusreply = message.createReply();
            dbusreply << ret;
            connection.send(dbusreply);
        } else {
            connection.send(ErrorAdaptor(error).createReply(message));
        }
    };
    m_parent->verifyUser(params, callback);
    context.setDelayedReply(true);
    return false; // ignored
}

bool SignonIdentityAdaptor::verifySecret(const QString &secret)
{
    const QDBusContext &context = parentDBusContext();
    QDBusConnection connection = context.connection();
    const QDBusMessage &message = context.message();

    /* Access Control */
    if (!AccessControlManagerHelper::instance()->isPeerAllowedToUseIdentity(
                                    connection,
                                    message,
                                    m_parent->id())) {
        securityErrorReply(__func__);
        return false;
    }

    bool verified = false;
    Error error = m_parent->verifySecret(secret, &verified);
    if (error) {
        connection.send(ErrorAdaptor(error).createReply(message));
    }
    return verified;
}

void SignonIdentityAdaptor::remove()
{
    const QDBusContext &context = parentDBusContext();
    QDBusConnection connection = context.connection();
    const QDBusMessage &message = context.message();

    /* Access Control */
    AccessControlManagerHelper::IdentityOwnership ownership =
            AccessControlManagerHelper::instance()->isPeerOwnerOfIdentity(
                                    connection,
                                    message,
                                    m_parent->id());

    if (ownership != AccessControlManagerHelper::IdentityDoesNotHaveOwner) {
        //Identity has an owner
        if (ownership == AccessControlManagerHelper::ApplicationIsNotOwner &&
            !AccessControlManagerHelper::instance()->isPeerKeychainWidget(
                                    connection,
                                    message)) {
            securityErrorReply(__func__);
            return;
        }
    }

    auto callback = [=](const Error &error) {
        if (!error) {
            connection.send(message.createReply());
        } else {
            connection.send(ErrorAdaptor(error).createReply(message));
        }
    };
    m_parent->remove(callback);
    context.setDelayedReply(true);
}

bool SignonIdentityAdaptor::signOut()
{
    const QDBusContext &context = parentDBusContext();
    QDBusConnection connection = context.connection();
    const QDBusMessage &message = context.message();

    /* Access Control */
    if (!AccessControlManagerHelper::instance()->isPeerAllowedToUseIdentity(
                                    connection,
                                    message,
                                    m_parent->id())) {
        securityErrorReply(__func__);
        return false;
    }

    auto callback = [=](bool signedOut, const Error &error) {
        if (!error) {
            QDBusMessage reply = message.createReply();
            reply << signedOut;
            connection.send(reply);
        } else {
            connection.send(ErrorAdaptor(error).createReply(message));
        }
    };
    m_parent->signOut(callback);
    context.setDelayedReply(true);
    return false; // ignored
}

quint32 SignonIdentityAdaptor::store(const QVariantMap &info)
{
    const QDBusContext &context = parentDBusContext();
    QDBusConnection connection = context.connection();
    const QDBusMessage &message = context.message();

    quint32 id = info.value(QLatin1String("Id"), SIGNOND_NEW_IDENTITY).toInt();
    /* Access Control */
    if (id != SIGNOND_NEW_IDENTITY) {
    AccessControlManagerHelper::IdentityOwnership ownership =
            AccessControlManagerHelper::instance()->isPeerOwnerOfIdentity(
                                    connection,
                                    message,
                                    m_parent->id());

        if (ownership != AccessControlManagerHelper::IdentityDoesNotHaveOwner) {
            //Identity has an owner
            if (ownership == AccessControlManagerHelper::ApplicationIsNotOwner &&
                !AccessControlManagerHelper::instance()->isPeerKeychainWidget(
                                    connection,
                                    message)) {

                securityErrorReply(__func__);
                return 0;
            }
        }
    }

    QString appId =
        AccessControlManagerHelper::instance()->appIdOfPeer(connection,
                                                            message);
    Error error = m_parent->store(info, appId, &id);
    if (error) {
        connection.send(ErrorAdaptor(error).createReply(message));
    }
    return id;
}

} //namespace SignonDaemonNS
