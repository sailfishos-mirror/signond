include( ../../common-project-config.pri )
include( ../../common-vars.pri )

TEMPLATE = app
TARGET = signon-utils
QT += core \
      dbus

QT -= gui

SOURCES += main.cpp

INCLUDEPATH += . \
    $${TOP_SRC_DIR}/src/plugins \

CONFIG += thread \
    debug_and_release \
    build_all \
    link_pkgconfig

QMAKE_CXXFLAGS += -fno-exceptions \
    -fno-rtti

DEFINES += QT_NO_CAST_TO_ASCII QT_NO_CAST_FROM_ASCII
LIBS += -lcreds

headers.files = $$HEADERS
include( ../../common-installs-config.pri )
