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

extern "C" {
#include <signal.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>
}

#include <remotepluginprocess.h>

using namespace RemotePluginProcessNS;

RemotePluginProcess *process = NULL;

void installSigHandlers()
{
    struct sigaction act;

    act.sa_handler = RemotePluginProcess::signalHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_flags |= SA_RESTART;

    sigaction(SIGHUP, &act, 0);
    sigaction(SIGTERM, &act, 0);
    sigaction(SIGINT, &act, 0);
}

int main(int argc, char *argv[])
{
    TRACE();

    QCoreApplication app(argc, argv);
    installSigHandlers();

    if (argc < 2) {
        TRACE() << "Type of plugin is not specified";
        exit(1);
    }

    QString type = app.arguments().at(1); TRACE() << type;

    fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL, 0) | O_NONBLOCK);
    fcntl(fileno(stdout), F_SETFL, fcntl(fileno(stdout), F_GETFL, 0) | O_NONBLOCK);

    process = RemotePluginProcess::createRemotePluginProcess(type, &app);

    if (!process)
        return 1;

    fprintf(stdout, "process started");
    fflush(stdout);

    QObject::connect(process, SIGNAL(processStopped()), &app, SLOT(quit()));
    return app.exec();
}