/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 *
 * Contact: Aurel Popirtac <ext-aurel.popirtac@nokia.com>
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
#include "signonidentityinfo.h"

#include <QBuffer>
#include <QDataStream>
#include <QDebug>

namespace SignonDaemonNS {

    SignonIdentityInfo::SignonIdentityInfo()
        : m_id(0),
          m_userName(QString()),
          m_password(QString()),
          m_caption(QString()),
          m_realms(QStringList()),
          m_accessControlList(QStringList()),
          m_type(0)
    {
    }

    SignonIdentityInfo::SignonIdentityInfo(const quint32 id, const QString &userName,
                const QString &password, const QMap<QString, QVariant> &methods,
                const QString &caption, const QStringList &realms,
                const QStringList &accessControlList, const int type)
        : m_id(id),
          m_userName(userName),
          m_password(password),
          m_caption(caption),
          m_realms(realms),
          m_methods(mapVariantToMapList(methods)),
          m_accessControlList(accessControlList),
          m_type(type)
    {
    }

    const QList<QVariant> SignonIdentityInfo::toVariantList()
    {
        QList<QVariant> list;
        list << m_id
             << m_userName
             << m_password
             << m_caption
             << m_realms
             << QVariant(mapListToMapVariant(m_methods))
             << m_accessControlList
             << m_type;

        return list;
    }

    const QList<QVariant> SignonIdentityInfo::listToVariantList(
            const QList<SignonIdentityInfo> &list)
    {
        QList<QVariant> variantList;
        foreach(SignonIdentityInfo info, list)
            variantList.append(QVariant(info.toVariantList())) ;
        return variantList;
    }

    const QMap<QString, QVariant> SignonIdentityInfo::mapListToMapVariant(
            const QMap<QString, QStringList> &mapList)
    {
        QMap<QString, QVariant> mapVariant;

        QMapIterator<QString, QStringList> it(mapList);
        while (it.hasNext()) {
            it.next();
            mapVariant.insert(it.key(), QVariant(it.value()));
        }
        return mapVariant;
    }

    const QMap<QString, QStringList> SignonIdentityInfo::mapVariantToMapList(
            const QMap<QString, QVariant> &mapVariant)
    {
        QMap<QString, QStringList> mapList;

        QMapIterator<QString, QVariant> it(mapVariant);
        while (it.hasNext()) {
            it.next();
            mapList.insert(it.key(), it.value().toStringList());
        }
        return mapList;
    }

    const QString SignonIdentityInfo::serialize()
    {
        QString serialized;
        QTextStream stream(&serialized);
        stream << QString::fromLatin1("SignondIdentityInfo serialized:\nID = %1, ").arg(m_id);
        stream << QString::fromLatin1("username = %1, ").arg(m_userName);
        stream << QString::fromLatin1("password = %1, ").arg(m_password);
        stream << QString::fromLatin1("caption = %1, ").arg(m_caption);
        stream << QString::fromLatin1("realms = %1, \n").arg(m_realms.join(QLatin1String(" ")));
        stream << QString::fromLatin1("acl = %1, \n").arg(m_accessControlList.join(QLatin1String(" ")));
        stream << QString::fromLatin1("type = %1, \n").arg(m_type);

        stream << "methods (";
        for (QMap<QString, QStringList>::iterator it = m_methods.begin();
             it != m_methods.end(); ++it) {
            stream << QString::fromLatin1("(%1, (%2))").arg(it.key()).arg(it.value().join(QLatin1String(",")));
        }
        stream << ")";

        return serialized;
    }


} //namespace SignonDaemonNS