/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler;

import sun.security.util.ObjectIdentifier;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class ObjectIdentifierHandler {
    private static Constructor<?> objectIdentifierConstructor;

    static {
        initObjectIdentifier();
    }

    private static void initObjectIdentifier() {
        try {
            Class<?> clazz = Class.forName("sun.security.util.ObjectIdentifier");
            objectIdentifierConstructor = clazz.getDeclaredConstructor(String.class);
            objectIdentifierConstructor.setAccessible(true);
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            // ignore
        }
    }

    private static String getStringOid(int[] values) {
        String ch = ".";
        StringBuilder stringOid = new StringBuilder();
        for (int value : values) {
            stringOid.append(value);
            stringOid.append(ch);
        }
        return stringOid.substring(0, stringOid.length() - 1);
    }

    /**
     * JDK 15.0.24 modify the ObjectIdentifier(String) constructor to private,
     * which cannot be accessed directly. For more information refer to
     * <a href="https://bugs.openjdk.org/browse/JDK-8242151">JDK-8242151</a>
     *
     * @param oid oid String
     * @return ObjectIdentifier
     * @throws java.io.IOException It is consistent with the original instance creation.
     *                             If the instance creation fails, an IOException is thrown.
     */
    public static ObjectIdentifier newObjectIdentifier(String oid) throws IOException {
        if (objectIdentifierConstructor == null) {
            throw new IOException("The sun.security.util.ObjectIdentifier class does not exist or the specified " +
                    "constructor does not exist");
        }

        try {
            return (ObjectIdentifier) objectIdentifierConstructor.newInstance(oid);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new IOException(e);
        }
    }

    public static ObjectIdentifier newObjectIdentifier(int[] values) throws IOException {
        String stringOid = getStringOid(values);
        return newObjectIdentifier(stringOid);
    }
}