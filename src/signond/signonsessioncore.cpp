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
#include "signonidentityinfo.h"
#include "signonidentity.h"
#include "signonauthsessionadaptor.h"
#include "signonui_interface.h"
#include "SignOn/uisessiondata_priv.h"

#define MAX_IDLE_TIME SSO_MAX_IDLE_TIME
/*
 * the watchdog searches for idle sessions with period of half of idle timeout
 * */
#define IDLE_WATCHDOG_TIMEOUT SSO_MAX_IDLE_TIME * 500

namespace SignonDaemonNS {

    /*
     * cache of session queues, as was mentined they cannot be static
     * */
    QMap<QString, SignonSessionCore *> sessionsOfStoredCredentials;

    /*
     * List of "zero" autsessions, needed for global signout
     * */
    QList<SignonSessionCore *> sessionsOfNonStoredCredentials;

    /*
     * idle sessions killer
     * */
    static QTimer idleKiller;
    static int subscribedSessions = 0;

    static QVariantMap filterVariantMap(const QVariantMap &other)
    {
        QVariantMap result;

        foreach(QString key, other.keys())
        {
            if (!other.value(key).isNull() && other.value(key).isValid())
                result.insert(key, other.value(key));
        }

        return result;
    }

    static QString sessionName(const quint32 id, const QString &method)
    {
       return QString(id) + QLatin1String("+") + method;
    }

    SignonSessionCore::SignonSessionCore(quint32 id, const QString &method, QObject *parent) :
                                           QObject(parent),
                                           m_id(id),
                                           m_method(method)
    {
        TRACE();
        m_signonui = NULL;
        m_watcher = NULL;
        isValid = false;

        SignonDaemon* daemon = qobject_cast<SignonDaemon *>(parent);

        if (!daemon)
            return;

        m_signonui = new SignonUiAdaptor(
                                        SIGNON_UI_SERVICE,
                                        SIGNON_UI_DAEMON_OBJECTPATH,
                                        QDBusConnection::sessionBus());

        m_lastOperationTime = QDateTime::currentDateTime();

        m_refCount = 0;
        isValid = true;
    }

    SignonSessionCore::~SignonSessionCore()
    {
        TRACE();

        delete m_plugin;
        delete m_watcher;
        delete m_signonui;

        m_plugin = NULL;
        m_signonui = NULL;
        m_watcher = NULL;
    }

    SignonSessionCore *SignonSessionCore::sessionCore(const quint32 id, const QString &method, SignonDaemon *parent)
    {
        TRACE();
        QString objectName;
        QString key = sessionName(id, method);

        if (id) {
            if (sessionsOfStoredCredentials.contains(key)) {
                return sessionsOfStoredCredentials.value(key);
            }
        }

        SignonSessionCore *ssc = new SignonSessionCore(id, method, parent);

        if (!ssc->isValid ||
            !ssc->setupPlugin()) {
            TRACE() << "The resulted object is corrupted and has to be deleted";
            delete ssc;
            return NULL;
        }

        if (id)
            sessionsOfStoredCredentials.insert(key, ssc);
        else
            sessionsOfNonStoredCredentials.append(ssc);

        TRACE() << "The new session is created :" << key;
        return ssc;
    }

    quint32 SignonSessionCore::id() const
    {
        TRACE();
        return m_id;
    }

    QString SignonSessionCore::method() const
    {
        TRACE();
        return m_method;
    }

    bool SignonSessionCore::setupPlugin()
    {
        m_plugin = PluginProxy::createNewPluginProxy(m_method);

        if (!m_plugin) {
            TRACE() << "Plugin of type " << m_method << " cannot be found";
            return false;
        }

        connect(m_plugin,
                SIGNAL(processResultReply(const QString&, const QVariantMap&)),
                this,
                SLOT(processResultReply(const QString&, const QVariantMap&)),
                Qt::DirectConnection);

        connect(m_plugin,
                SIGNAL(processUiRequest(const QString&, const QVariantMap&)),
                this,
                SLOT(processUiRequest(const QString&, const QVariantMap&)),
                Qt::DirectConnection);

        connect(m_plugin,
                SIGNAL(processRefreshRequest(const QString&, const QVariantMap&)),
                this,
                SLOT(processRefreshRequest(const QString&, const QVariantMap&)),
                Qt::DirectConnection);

        connect(m_plugin,
                SIGNAL(processError(const QString&, int, const QString&)),
                this,
                SLOT(processError(const QString&, int, const QString&)),
                Qt::DirectConnection);

        connect(m_plugin,
                SIGNAL(stateChanged(const QString&, int, const QString&)),
                this,
                SLOT(stateChangedSlot(const QString&, int, const QString&)),
                Qt::DirectConnection);

        return true;
    }

    void SignonSessionCore::stopAllAuthSessions()
    {
        qDeleteAll(sessionsOfStoredCredentials);
        sessionsOfStoredCredentials.clear();

        qDeleteAll(sessionsOfNonStoredCredentials);
        sessionsOfNonStoredCredentials.clear();
    }

    void SignonSessionCore::subscribeWatchdog(SignonSessionCore *subscriber)
    {
        if (!idleKiller.isActive())
            idleKiller.start(IDLE_WATCHDOG_TIMEOUT);

        connect(&idleKiller, SIGNAL(timeout()), subscriber, SLOT(checkForIdle()));
        subscribedSessions++;
    }

    void SignonSessionCore::unsubscribeWatchdog(SignonSessionCore *unsubscriber)
    {
        disconnect(&idleKiller, SIGNAL(timeout()), unsubscriber, SLOT(checkForIdle()));
        subscribedSessions = (subscribedSessions > 0 ? subscribedSessions -1 : 0);

        if (!subscribedSessions && idleKiller.isActive())
            idleKiller.stop();
    }

    QStringList SignonSessionCore::loadedPluginMethods(const QString &method)
    {
        foreach (SignonSessionCore *corePtr, sessionsOfStoredCredentials) {
            if (corePtr->method() == method)
                return corePtr->queryAvailableMechanisms(QStringList());
        }

        foreach (SignonSessionCore *corePtr, sessionsOfNonStoredCredentials) {
            if (corePtr->method() == method)
                return corePtr->queryAvailableMechanisms(QStringList());
        }

        return QStringList();
    }

    QStringList SignonSessionCore::queryAvailableMechanisms(const QStringList &wantedMechanisms)
    {
        m_lastOperationTime = QDateTime::currentDateTime();

        if (!wantedMechanisms.size())
            return m_plugin->mechanisms();

        return m_plugin->mechanisms().toSet().intersect(wantedMechanisms.toSet()).toList();
    }

    void SignonSessionCore::process(const QDBusConnection &connection,
                                     const QDBusMessage &message,
                                     const QVariantMap& sessionDataVa,
                                     const QString& mechanism,
                                     const QString& cancelKey)
    {
        TRACE();

        RequestData rd(connection, message, sessionDataVa, mechanism, cancelKey);
        m_listOfRequests.enqueue(rd);

        QMetaObject::invokeMethod(this, "startNewRequest", Qt::QueuedConnection);
        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::cancel(const QString &cancelKey)
    {
        TRACE();
        int requestIndex;

        for (requestIndex = 0; requestIndex < m_listOfRequests.size(); requestIndex++) {
            if (m_listOfRequests.at(requestIndex).m_cancelKey == cancelKey)
                break;
        }

        TRACE() << "The request is found with index " << requestIndex;

        if (requestIndex < m_listOfRequests.size()) {
            if (requestIndex == 0) {
                m_cancelled = cancelKey;
                m_plugin->cancel();

                if (m_watcher && !m_watcher->isFinished()) {
                    m_signonui->cancelUiRequest(cancelKey);
                    delete m_watcher;
                    m_watcher = 0;
                }
            }

            /*
             * We must let to the m_listOfRequests to have the cancelled request data
             * in order to delay the next request execution until the actual cancellation
             * will happen. We will know about that precisely: plugin must reply via
             * resultSlot or via errorSlot.
             * */
            RequestData rd((requestIndex == 0 ?
                            m_listOfRequests.head() :
                            m_listOfRequests.takeAt(requestIndex)));

            QDBusMessage errReply = rd.m_msg.createErrorReply(QLatin1String("com.nokia.singlesignon.AuthSessionError.CancelledError"),
                                                              QLatin1String("process is cancelled"));
            rd.m_conn.send(errReply);
            TRACE() << "Size of the queue is " << m_listOfRequests.size();
        }

        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::setId(quint32 id)
    {
        QString key = sessionName(id, m_method);

        if (m_id || sessionsOfStoredCredentials.contains(key)) {
            qCritical() << "attempt to assign existing id";
            return;
        }

        m_id = id;
        sessionsOfStoredCredentials[key] = this;
        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::startProcess()
    {
        TRACE() << "the number of requests is : " << m_listOfRequests.length();
        RequestData data = m_listOfRequests.head();

        QVariantMap parameters = data.m_params;

        if (m_id) {
            CredentialsDB *db = qobject_cast<SignonDaemon*>(parent())->m_pCAMManager->credentialsDB();
            SignonIdentityInfo info = db->credentials(m_id);
            if (!db->errorOccurred()) {
                /*
                 * TODO: reconsider this code: maybe some more data is required
                 * */
                parameters[QLatin1String("Secret")] = info.m_password;
                parameters[QLatin1String("UserName")] = info.m_userName;
            } else {
                qCritical() << "!!!problems with getting data from credentials database!!!";
                /*
                 * TODO: actual behavior should be clarified for this case
                 * */
            }
        }

        if (!m_plugin->process(data.m_cancelKey, parameters, data.m_mechanism)) {
            QDBusMessage errReply = data.m_msg.createErrorReply(runtimeErrorName,
                                                                runtimeErrorMsg);
            data.m_conn.send(errReply);
            m_listOfRequests.removeFirst();
            QMetaObject::invokeMethod(this, "startNewRequest", Qt::QueuedConnection);
        } else
            stateChangedSlot(data.m_cancelKey, SignOn::SessionStarted, QLatin1String("The request is started successfully"));

        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::replyError(const QDBusConnection &conn, const QDBusMessage &msg, int err, const QString &message)
    {
        QString errName;
        QString errMessage;

        switch (err) {
            case PLUGIN_ERROR_INVALID_STATE:
                errMessage = wrongStateErrorMsg;
                errName = wrongStateErrorName;
                break;
            case PLUGIN_ERROR_NOT_AUTHORIZED:
                errMessage = invalidCredentialsErrorMsg;
                errName = invalidCredentialsErrorName;
                break;
            case PLUGIN_ERROR_PERMISSION_DENIED:
                errMessage = permissionDeniedErrorMsg;
                errName = permissionDeniedErrorName;
                break;
            case PLUGIN_ERROR_NO_CONNECTION:
                errMessage = noConnectionErrorMsg;
                errName = noConnectionErrorName;
                break;
            case PLUGIN_ERROR_NETWORK_ERROR:
                errMessage = networkErrorMsg;
                errName = networkErrorName;
                break;
            case PLUGIN_ERROR_SSL_ERROR:
                errMessage = sslErrorMsg;
                errName = sslErrorName;
                break;
            case PLUGIN_ERROR_OPERATION_FAILED:
                errMessage = operationNotSupportedErrorMsg;
                errName = operationNotSupportedErrorName;
                break;
             case PLUGIN_ERROR_MISSING_DATA:
                errMessage = missingDataErrorMsg;
                errName = missingDataErrorName;
                break;
            case PLUGIN_ERROR_MECHANISM_NOT_SUPPORTED:
                errMessage = mechanismNotAvailableErrorMsg;
                errName = mechanismNotAvailableErrorName;
                break;
            case PLUGIN_ERROR_RUNTIME:
                errMessage = runtimeErrorMsg;
                errName = runtimeErrorName;
                break;
            default:
                errName = unknownErrorName;
                errMessage = unknownErrorMsg;
                break;
        };

        QDBusMessage errReply = msg.createErrorReply(errName, ( message.isEmpty() ? errMessage : message ));
        conn.send(errReply);
    }

    void SignonSessionCore::processResultReply(const QString &cancelKey, const QVariantMap &data)
    {
        TRACE();

        if (!m_listOfRequests.size())
            return;

        RequestData rd = m_listOfRequests.dequeue();

        if (cancelKey != m_cancelled) {
            QVariantList arguments;
            QVariantMap data2 = filterVariantMap(data);

            if (m_method != QLatin1String("password") && data2.contains(QLatin1String("Secret")))
                data2.remove(QLatin1String("Secret"));

            arguments << data2;

            TRACE() << "sending reply: " << arguments;
            rd.m_conn.send(rd.m_msg.createReply(arguments));
            m_cancelled = QString();

            if (m_watcher && !m_watcher->isFinished()) {
                m_signonui->cancelUiRequest(rd.m_cancelKey);
                delete m_watcher;
                m_watcher = 0;
            }
        }

        m_cancelled = QString();
        QMetaObject::invokeMethod(this, "startNewRequest", Qt::QueuedConnection);
        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::processUiRequest(const QString &cancelKey, const QVariantMap &data)
    {
        TRACE();

        if (cancelKey != m_cancelled && m_listOfRequests.size()) {
            QString uiRequestId = m_listOfRequests.head().m_cancelKey;

            if (m_watcher) {
                if (!m_watcher->isFinished())
                    m_signonui->cancelUiRequest(uiRequestId);

                delete m_watcher;
                m_watcher = 0;
            }

            m_listOfRequests.head().m_params = filterVariantMap(data);
            m_listOfRequests.head().m_params[SSOUI_KEY_REQUESTID] = uiRequestId;

            if (!m_id && m_listOfRequests.head().m_params.contains(SSOUI_KEY_REMEMBER))
                m_listOfRequests.head().m_params.remove(SSOUI_KEY_REMEMBER);

                //TODO: figure out how we going to synchronize
                //different login dialogs in order not to show
                //multiple login dialogs for the same credentials
    //            data2["CredentialsId"] = m_id;
            m_watcher = new QDBusPendingCallWatcher(m_signonui->queryDialog(m_listOfRequests.head().m_params),
                                                    this);
            connect(m_watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(queryUiSlot(QDBusPendingCallWatcher*)));
        }

        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::processRefreshRequest(const QString &cancelKey, const QVariantMap &data)
    {
        TRACE();

        if (cancelKey != m_cancelled && m_listOfRequests.size()) {
            QString uiRequestId = m_listOfRequests.head().m_cancelKey;

            if (m_watcher) {
                if (!m_watcher->isFinished())
                    m_signonui->cancelUiRequest(uiRequestId);

                delete m_watcher;
                m_watcher = 0;
            }

            m_listOfRequests.head().m_params = filterVariantMap(data);
            m_watcher = new QDBusPendingCallWatcher(m_signonui->refreshDialog(m_listOfRequests.head().m_params),
                                                    this);
            connect(m_watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(queryUiSlot(QDBusPendingCallWatcher*)));
        }

        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::processError(const QString &cancelKey, int err, const QString &message)
    {
        TRACE();

        if (!m_listOfRequests.size())
            return;

        RequestData rd = m_listOfRequests.dequeue();

        if (cancelKey != m_cancelled) {
            replyError(rd.m_conn, rd.m_msg, err, message);

            if (m_watcher && !m_watcher->isFinished()) {
                m_signonui->cancelUiRequest(rd.m_cancelKey);
                delete m_watcher;
                m_watcher = 0;
            }
        }

        m_cancelled = QString();
        QMetaObject::invokeMethod(this, "startNewRequest", Qt::QueuedConnection);
        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::stateChangedSlot(const QString &cancelKey, int state, const QString &message)
    {
        if (cancelKey != m_cancelled && m_listOfRequests.size()) {
            RequestData rd = m_listOfRequests.head();
            emit stateChanged(rd.m_cancelKey, (int)state, message);
        }

        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::childEvent(QChildEvent *ce)
    {
        TRACE();
        if (ce->removed()) {
            m_refCount--;
            if (m_refCount == 0)
                subscribeWatchdog(this);

            TRACE() << "removed: " << m_refCount;
        } else if (ce->added()) {
            if (m_refCount == 0)
                unsubscribeWatchdog(this);

            m_refCount++;

            TRACE() << "added: " << m_refCount;
        }
    }

    void SignonSessionCore::checkForIdle()
    {
        TRACE();
        QDateTime currentTime = QDateTime::currentDateTime();

        if (currentTime.toTime_t() - m_lastOperationTime.toTime_t() <= MAX_IDLE_TIME)
            return;

        TRACE() << "The given AuthSession is idle for too long time";

        if (m_id)
            sessionsOfStoredCredentials.remove(sessionName(m_id, m_method));
        else
            sessionsOfNonStoredCredentials.removeOne(this);

        delete this;
    }

    void SignonSessionCore::queryUiSlot(QDBusPendingCallWatcher *call)
    {
        TRACE();
        QDBusPendingReply<QVariantMap> reply = *call;
        bool isRequestToRefresh = false;
        Q_ASSERT_X( m_listOfRequests.size() != 0, __func__, "queue of requests is empty");

        if (!reply.isError() && reply.count()) {
            QVariantMap resultParameters = reply.argumentAt<0>();
            if (resultParameters.contains(SSOUI_KEY_REFRESH)) {
                isRequestToRefresh = true;
                resultParameters.remove(SSOUI_KEY_REFRESH);
            }

            if (resultParameters.contains(SSOUI_KEY_REMEMBER) &&
               resultParameters[SSOUI_KEY_REMEMBER].toBool() ) {
                if (parent()->m_storedIdentities.contains(m_id)) {
                    SignonIdentity *idty = parent()->m_storedIdentities.value(m_id);

                    if (idty) {
                        bool isOk;
                        SignonIdentityInfo info = idty->queryInfo(isOk);

                        if (isOk) {
                            QString newUsername = resultParameters[SSOUI_KEY_USERNAME].toString();
                            QString newSecret = resultParameters[SSOUI_KEY_PASSWORD].toString();

                            idty->storeCredentials(m_id,
                                                   newUsername,
                                                   newSecret,
                                                   info.m_password.isEmpty(),
                                                   SignonIdentityInfo::mapListToMapVariant(info.m_methods),
                                                   info.m_caption,
                                                   info.m_realms,
                                                   info.m_accessControlList,
                                                   info.m_type);
                        }
                    }
                }
                resultParameters.remove(SSOUI_KEY_REMEMBER);
            }
            m_listOfRequests.head().m_params = resultParameters;
        } else
            m_listOfRequests.head().m_params.insert(SSOUI_KEY_ERROR, (int)SignOn::QUERY_ERROR_NO_SIGNONUI);

        TRACE() << m_listOfRequests.head().m_params;

        if (m_listOfRequests.head().m_cancelKey != m_cancelled) {
            if (isRequestToRefresh) {
                TRACE() << "REFRESH IS REQUIRED";

                m_listOfRequests.head().m_params.remove(SSOUI_KEY_REFRESH);
                m_plugin->processRefresh(m_listOfRequests.head().m_cancelKey,
                                         m_listOfRequests.head().m_params);
            } else {
                m_plugin->processUi(m_listOfRequests.head().m_cancelKey,
                                    m_listOfRequests.head().m_params);
            }
        }

        delete m_watcher;
        m_watcher = NULL;

        m_lastOperationTime = QDateTime::currentDateTime();
    }

    void SignonSessionCore::startNewRequest()
    {
        m_lastOperationTime = QDateTime::currentDateTime();

        // there is no request
        if (!m_listOfRequests.length()) {
            TRACE() << "the data queue is EMPTY!!!";
            return;
        }

        //plugin is busy
        if (m_plugin && m_plugin->isProcessing()) {
            TRACE() << " the plugin is in challenge processing";
            return;
        }

        //there is some UI operation with plugin
        if (m_watcher && !m_watcher->isFinished()) {
            TRACE() << "watcher is in running mode";
            return;
        }

        TRACE() << "Start the authentication process";
        startProcess();
    }
} //namespace SignonDaemonNS