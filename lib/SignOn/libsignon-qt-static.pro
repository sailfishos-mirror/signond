include( ../../common-project-config.pri )
include( ../../common-vars.pri )
TEMPLATE = lib
TARGET = signon-qt

# Input
public_headers += \
                  sessiondata.h \
                  identityinfo.h \
                  authservice.h \
                  identity.h \
                  authsession.h \
                  libsignoncommon.h \
                  signon.h

private_headers = authserviceimpl.h \
                  identityimpl.h \
                  authsessionimpl.h \
                  identityinfoimpl.h \
                  dbusoperationqueuehandler.h

HEADERS = $$public_headers \
    $$private_headers

INCLUDEPATH += . \
    $$TOP_SRC_DIR/include

SOURCES += identityinfo.cpp \
    identity.cpp \
    identityimpl.cpp \
    authservice.cpp \
    authserviceimpl.cpp \
    authsession.cpp \
    authsessionimpl.cpp \
    identityinfoimpl.cpp \
    dbusoperationqueuehandler.cpp

QT += core \
      dbus

QT -= gui

CONFIG += qdbus \
    static \
    debug_and_release \
    build_all \
    link_pkgconfig
QMAKE_CXXFLAGS += -fno-exceptions \
    -fno-rtti
DEFINES += QT_NO_CAST_TO_ASCII QT_NO_CAST_FROM_ASCII

include( ../../common-installs-config.pri )

headers.files = $$public_headers \
	AuthService \
	AuthSession \
	Identity \
	SessionData
headers.path = $${INSTALL_PREFIX}/include/signon-qt/SignOn
INSTALLS += headers

pkgconfig.files = libsignon-qt.pc
pkgconfig.path = $${INSTALL_PREFIX}/lib/pkgconfig
INSTALLS += pkgconfig