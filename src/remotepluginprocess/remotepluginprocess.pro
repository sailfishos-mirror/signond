include( ../../common-project-config.pri )
include( ../../common-vars.pri )
TEMPLATE = app
TARGET = signonpluginprocess
QT += core network
QT -= gui

HEADERS += remotepluginprocess.h

SOURCES += main.cpp \
           remotepluginprocess.cpp

INCLUDEPATH += . \
               $$TOP_SRC_DIR/src \
               $$TOP_SRC_DIR/src/plugins \
               $$TOP_SRC_DIR/src/signond \
               $$TOP_SRC_DIR/lib/plugins

CONFIG +=  debug_and_release \
           build_all \
           link_pkgconfig

QMAKE_CXXFLAGS += -fno-exceptions \
                  -fno-rtti

include( ../../common-installs-config.pri )