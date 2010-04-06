include( ../../common-project-config.pri )
include( ../../common-vars.pri )
TARGET = signon-plugins-tests
QT += core \
    dbus
CONFIG += qtestlib \
    link_pkgconfig

SOURCES += authpluginstest.cpp \
    authpluginspool.cpp \
    $${TOP_SRC_DIR}/src/signond/pluginproxy.cpp

HEADERS += authpluginstest.h \
    $${TOP_SRC_DIR}/src/signond/pluginproxy.h \
    authpluginspool.h
INCLUDEPATH += $${TOP_SRC_DIR}/src/signond \
    $${TOP_SRC_DIR}/lib/plugins \
    $${TOP_SRC_DIR}/src/plugins

QMAKE_CXXFLAGS += -fno-exceptions \
    -fno-rtti
#OTHER_FILES += run-test.sh
target.path = /usr/bin

testsuite.path  = /usr/share/$$TARGET
testsuite.files = tests.xml config.txt

INSTALLS += target \
            testsuite