/* -*- Mode: C++; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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

/*!
 * @file simdatahandler.h
 * @brief Definition of the SIM data handler object.
 */

#ifndef SIMDATAHANDLER_H
#define SIMDATAHANDLER_H

#include <QObject>

#include <SIM>
using namespace Cellular::SIM;


/*!
 * @class SimDataHandler
 * SimDataHandler handles acquaring data from the device SIM card
 * which is used by the CryptoManager as a key for the mounting of the encrypted file system.
 * @ingroup Accounts_and_SSO_Framework
 * SimDataHandler inherits QObject.
 * @sa CryptoManager
 */
class SimDataHandler: public QObject
{
    Q_OBJECT

public:
    /*!
      * Constructs a SimDataHandler object with the given parent.
      * @param parent The parent object.
      */
    SimDataHandler(QObject *parent = 0);

    /*!
      * Destructor, releases allocated resources.
      */
    virtual ~SimDataHandler();

    /*!
      * @returns true upon success.
      */
    bool isValid();

    /*!
      * @returns whether the SIM card is fully inserted in the device or not.
      */
    bool isSimPresent();

    /*!
      * @returns whether the SIM card is present and we've got its data.
      */
    bool isSimActive();

    /*!
      * Queries the SIM for authentication info
      * @sa simAvailable(const QByteArray &simData) is emitted if the query is successful.
      * @sa error() is emitted otherwise.
      */
    void querySim();

Q_SIGNALS:
    /*!
        Is emitted when a the SIM data is available.
        Can be triggered because of a successful explicit querySim call,
        or automatically in the case the SIM has been changed.
        @param simData, the SIM's data.
    */
    void simAvailable(const QByteArray simData);

    /*!
        Emitted when SIM was removed.
     */
    void simRemoved(const QByteArray simData);

    /*!
        Emitted when SIM challenge fails.
     */
    void error();

private Q_SLOTS:
    void authComplete(
        QByteArray res,
        QByteArray cipheringKey,
        QByteArray eapCipheringKey,
        QByteArray eapIntegrityKey,
        SIMError error);

    void simStatusChanged(SIMStatus::Status status);
    void simStatusComplete(SIMStatus::Status status, SIMError err);

private:
    void refreshSimIdentity();

private:
    QByteArray m_dataBuffer;
    QByteArray simData;
    bool m_simChallengeComplete;
    int m_randCounter;

    SIMStatus::Status m_lastSimStatus;
    SIMIdentity *m_simIdentity;
    SIMStatus *m_simStatus;
};

#endif // SIMDATAHANDLER_H