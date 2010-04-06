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

#include "signonui_interface.h"

/*
 * Implementation of interface class SignonUiAdaptor
 */

SignonUiAdaptor::SignonUiAdaptor(const QString &service, const QString &path, const QDBusConnection &connection, QObject *parent)
    : QDBusAbstractInterface(service, path, staticInterfaceName(), connection, parent)
{
}

SignonUiAdaptor::~SignonUiAdaptor()
{
}

/*
 * Open a new dialog
 * */

QDBusPendingCall SignonUiAdaptor::queryDialog(const QVariantMap &parameters)
{
    QList<QVariant> argumentList;
    argumentList << parameters;
    return callWithArgumentListAndBigTimeout(QLatin1String("queryDialog"), argumentList);
}


/*
 * update the existing dialog
 * */
QDBusPendingCall SignonUiAdaptor::refreshDialog(const QVariantMap &parameters)
{
    QList<QVariant> argumentList;
    argumentList << parameters;
    return callWithArgumentListAndBigTimeout(QLatin1String("refreshDialog"), argumentList);
}


/*
 * cancel dialog request
 * */
void SignonUiAdaptor::cancelUiRequest(const QString &requestId)
{
    QList<QVariant> argumentList;
    argumentList << requestId;
    callWithArgumentList(QDBus::NoBlock, QLatin1String("cancelUiRequest"), argumentList);
}

QDBusPendingCall SignonUiAdaptor::callWithArgumentListAndBigTimeout(const QString &method,
                                                         const QList<QVariant> &args)
{
    QDBusMessage msg = QDBusMessage::createMethodCall(service(),
                                                      path(),
                                                      interface(),
                                                      method);
    msg.setArguments(args);
    return connection().asyncCall(msg, SIGNON_MAX_TIMEOUT);
}