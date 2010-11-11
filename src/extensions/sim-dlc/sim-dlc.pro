include( ../../../common-project-config.pri )
include( $${TOP_SRC_DIR}/common-vars.pri )
include( $${TOP_SRC_DIR}/common-installs-config.pri )

TEMPLATE = lib
TARGET = sim-dlc

CONFIG += \
    qt \
    plugin

QT += \
    core \
    dbus
QT -= gui

PKGCONFIG += CellularQt

INCLUDEPATH += . \
    $${TOP_SRC_DIR}/lib/signond \
    $${TOP_SRC_DIR}/lib/sim-dlc
LIBS += -lsignon-extension

HEADERS = \
    debug.h \
    device-lock-code-handler.h \
    key-manager.h \
    sim-data-handler.h \
    sim-dlc-plugin.h

SOURCES = \
    device-lock-code-handler.cpp \
    key-manager.cpp \
    sim-data-handler.cpp \
    sim-dlc-plugin.cpp

target.path = $${INSTALL_PREFIX}/lib/signon/extensions
INSTALLS = target

service.path = $${INSTALL_PREFIX}/share/dbus-1/services
service.files = com.nokia.SingleSignOn.DeviceLock.service
INSTALLS += service
