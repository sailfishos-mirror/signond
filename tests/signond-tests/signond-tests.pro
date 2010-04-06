include( ../../common-project-config.pri )
include( $$TOP_SRC_DIR/common-vars.pri )

CONFIG += qtestlib qdbus

QT += core \
    sql \
    xml \
    network \
    dbus

QT -= gui

LIBS += -L/usr/lib \
        -lcreds

#DEFINES += CAM_UNIT_TESTS_FIXED

HEADERS += \
           $$TOP_SRC_DIR/src/signond/pluginproxy.h \
           $$TOP_SRC_DIR/tests/pluginproxytest/testpluginproxy.h

SOURCES =  signond-tests.cpp \
	   $$TOP_SRC_DIR/tests/pluginproxytest/testpluginproxy.cpp \
           $$TOP_SRC_DIR/tests/pluginproxytest/include.cpp
           

contains(DEFINES, CAM_UNIT_TESTS_FIXED) {
 HEADERS *=$$TOP_SRC_DIR/tests/credentialsaccessmanagertest/cam-test-server/credentialsaccessmanagertest.h \
           $$TOP_SRC_DIR/tests/credentialsaccessmanagertest/cam-test-server/dbuspeer.h \
           $$TOP_SRC_DIR/tests/credentialsaccessmanagertest/defs.h \
           $$TOP_SRC_DIR/src/signond/credentialsaccessmanager.h \
           $$TOP_SRC_DIR/src/signond/accesscodehandler.h \
           $$TOP_SRC_DIR/src/signond/simdbusadaptor.h \
           $$TOP_SRC_DIR/src/signond/cryptomanager.h \
           $$TOP_SRC_DIR/src/signond/credentialsdb.h
           
 SOURCES *= $$TOP_SRC_DIR/tests/credentialsaccessmanagertest/cam-test-server/credentialsaccessmanagertest.cpp \
            $$TOP_SRC_DIR/tests/credentialsaccessmanagertest/cam-test-server/includes.cpp \
            $$TOP_SRC_DIR/tests/credentialsaccessmanagertest/cam-test-server/dbuspeer.cpp
}

TARGET = signond-tests

INCLUDEPATH += . \
    $$TOP_SRC_DIR/lib/plugins \
    $$TOP_SRC_DIR/tests/pluginproxytest \
    $$TOP_SRC_DIR/src/signond \
    $$TOP_SRC_DIR/tests/credentialsaccessmanagertest/cam-test-server
    
DEFINES += SSO_CI_TESTMANAGEMENT

QMAKE_CXXFLAGS += -fno-exceptions \
    -fno-rtti

target.path = /usr/bin

testsuite.path  = /usr/share/$$TARGET
testsuite.files = tests.xml
          
INSTALLS += target \
            testsuite