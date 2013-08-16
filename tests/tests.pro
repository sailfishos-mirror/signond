include( ../common-project-config.pri )
include( ../common-vars.pri )

TEMPLATE = subdirs

CONFIG  += ordered

SUBDIRS += \
    passwordplugintest \
    libsignon-qt-tests \
    signond-tests \
    extensions

QMAKE_SUBSTITUTES += com.google.code.AccountsSSO.SingleSignOn.service.in
