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
#include "testauthserviceresult.h"


#define YUPYYYY qDebug() << "Reply from SIGNON DAEMON---------------------------------" << __FUNCTION__;

TestAuthServiceResult::TestAuthServiceResult()
{
    reset();
}

void TestAuthServiceResult::reset()
{
    m_responseReceived = Inexistent;
    m_err = AuthService::UnknownError;
    m_errMsg = "";

    m_identities.clear();
    m_methods.clear();
    m_mechanisms.first = QString();
    m_mechanisms.second.clear();
    m_cleared = false;
}

void TestAuthServiceResult::error(AuthService::ServiceError code, const QString& message)
{
    YUPYYYY
    m_responseReceived = Error;
    m_err = code;
    m_errMsg = message;

    TRACE() << "Error:" << m_err << ", Message:" << m_errMsg;

    emit testCompleted();
}

void TestAuthServiceResult::methodsAvailable(const QStringList &methods)
{
    YUPYYYY
    m_responseReceived = Normal;
    m_methods = methods;

    emit testCompleted();
}

void TestAuthServiceResult::mechanismsAvailable(const QString &method, const QStringList &mechanisms)
{
    YUPYYYY
    m_responseReceived = Normal;
    m_mechanisms.first = method;
    m_mechanisms.second = mechanisms;
    m_queriedMechsMethod = method;

    emit testCompleted();
}

void TestAuthServiceResult::identities(const QList<IdentityInfo> &identityList)
{
    YUPYYYY
    m_responseReceived = Normal;
    m_identities = identityList;

    emit testCompleted();
}

void TestAuthServiceResult::cleared()
{
    YUPYYYY
    m_responseReceived = Normal;
    m_cleared = true;

    emit testCompleted();
}
