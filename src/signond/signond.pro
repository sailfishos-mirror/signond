include( ../../common-project-config.pri )
include( ../../common-vars.pri )
TEMPLATE = app
TARGET = signond
QT += core \
    sql \
    xml \
    network \
    dbus
QT -= gui
HEADERS += \
    accesscodehandler.h \
    accesscontrolmanager.h \
    credentialsaccessmanager.h \
    credentialsdb.h \
    cryptomanager.h \
    cryptohandlers.h \
    signonsessioncore.h \
    signonauthsessionadaptor.h \
    signonauthsession.h \
    signonidentity.h \
    signond-common.h \
    signondaemonadaptor.h \
    signondaemon.h \
    signontrace.h \
    simdbusadaptor.h \
    pluginproxy.h \
    signonidentityinfo.h \
    signonui_interface.h \
    signonidentityadaptor.h
SOURCES += accesscodehandler.cpp \
    accesscontrolmanager.cpp \
    credentialsaccessmanager.cpp \
    credentialsdb.cpp \
    cryptomanager.cpp \
    cryptohandlers.cpp \
    simdbusadaptor.cpp \
    signonsessioncore.cpp \
    signonauthsessionadaptor.cpp \
    signonauthsession.cpp \
    signonidentity.cpp \
    signondaemonadaptor.cpp \
    signonui_interface.cpp \
    pluginproxy.cpp \
    main.cpp \
    signondaemon.cpp \
    signonidentityinfo.cpp \
    signonidentityadaptor.cpp
INCLUDEPATH += . \
    $${TOP_SRC_DIR}/lib/plugins

CONFIG += thread \
    debug_and_release \
    build_all \
    link_pkgconfig
QMAKE_CXXFLAGS += -fno-exceptions \
    -fno-rtti
DEFINES += QT_NO_CAST_TO_ASCII QT_NO_CAST_FROM_ASCII
LIBS += -lcreds -lcryptsetup
headers.files = $$HEADERS
include( ../../common-installs-config.pri )

# Disabling access control if platform is not arm
BUILD_ARCH = $$QMAKE_HOST.arch
contains(BUILD_ARCH, i686):DEFINES += SIGNON_DISABLE_ACCESS_CONTROL
else:# TODO get rid of the 'else' branch after security fixes.
DEFINES += SIGNON_DISABLE_ACCESS_CONTROL