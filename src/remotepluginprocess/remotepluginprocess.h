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

#ifndef REMOTEPLUGINPROCESS_H
#define REMOTEPLUGINPROCESS_H

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <QDataStream>
#include <QByteArray>
#include <QVariant>
#include <QMap>
#include <QIODevice>
#include <QFile>
#include <QDir>
#include <QLibrary>
#include <QSocketNotifier>
#include <QThread>

#include "SignOn/signoncommon.h"
#include "SignOn/uisessiondata.h"
#include "SignOn/authpluginif.h"
#include "SignOn/signonplugin.h"

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
}

#ifndef SIGNON_PLUGINS_DIR
      #define SIGNON_PLUGINS_DIR "/usr/lib/signon"
#endif

#ifndef SIGNON_PLUGIN_PREFIX
    #define SIGNON_PLUGIN_PREFIX "lib"
#endif

#ifndef SIGNON_PLUGIN_SUFFIX
    #define SIGNON_PLUGIN_SUFFIX "plugin.so"
#endif

#ifndef SIGNON_PLUGINS_DIR
    #define SIGNON_PLUGINS_DIR "/usr/lib/signon"
#endif



namespace RemotePluginProcessNS {

/*!
 * @class CancelEventThread
 * Thread to enable cancel functionality.
 */
 class CancelEventThread : public QThread
{
    Q_OBJECT

    public:
        CancelEventThread(AuthPluginInterface *plugin);
        ~CancelEventThread();

    void run();

    public Q_SLOTS:
      void cancel();

    private:
        AuthPluginInterface *m_plugin;
        QSocketNotifier *m_cancelNotifier;
};

/*!
 * @class RemotePluginProcess
 * Class to execute plugin process.
 */
class RemotePluginProcess : public QObject
{
    Q_OBJECT

    public:
        RemotePluginProcess(QObject *parent);
        ~RemotePluginProcess();

        static RemotePluginProcess* createRemotePluginProcess(QString &type, QObject *parent);

        // Unix signal handler.
        static void signalHandler(int signal);

        bool loadPlugin(QString &type);
        bool setupDataStreams();
        bool setupSignalHandlers();
        bool setupProxySettings();

    void challenge(QDataStream &in, QDataStream &out);

    public Q_SLOTS:

        void startTask();
        void handleSignal();

    private:
        AuthPluginInterface *m_plugin;

        QFile m_infile;
        QSocketNotifier *m_readnotifier;
        QSocketNotifier *m_errnotifier;

        QFile m_outfile;

        QSocketNotifier *sn;

//        //current arguments for process
//        SignOn::SessionData m_data;
//        QString m_mechanism;

        QString getPluginName(const QString &type);
        void type();
        void mechanism();
        void mechanisms();

        void process();
        void userActionFinished();
        void refresh();

        void enableCancelThread();
        void disableCancelThread();

    private Q_SLOTS:
        void result(const SignOn::SessionData &data);
        void error(const AuthPluginError error, const QString &errorMessage);
        void userActionRequired(const SignOn::UiSessionData &data);
        void refreshed(const SignOn::UiSessionData &data);
        void statusChanged(const AuthPluginState state, const QString &message);

    Q_SIGNALS :
        void processStopped();

};

} //namespace RemotePluginProcessNS

#endif /* REMOTEPLUGINPROCESS_H */