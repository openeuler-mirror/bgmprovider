/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

import sun.security.util.Debug;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;


import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Map;

import static org.openeuler.ObjectIdentifierHandler.newObjectIdentifier;

public class BGMJCEProvider extends AbstractProvider {
    private static final Debug debug = Debug.getInstance("Provider");

    static {
        initNameTable();
    }

    @SuppressWarnings("unchecked")
    private static void initNameTable() {
        try {
            Field nameTableFiled = AlgorithmId.class.getDeclaredField("nameTable");
            nameTableFiled.setAccessible(true);
            Object object = nameTableFiled.get(null);
            if (!(object instanceof Map)) {
                return;
            }
            Map<ObjectIdentifier, String> nameTable = (Map<ObjectIdentifier, String>) object;
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.104"), "SM4");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.301"), "SM2");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.401"), "SM3");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.501"), "SM3withSM2");
        } catch (NoSuchFieldException | IllegalAccessException | IOException e) {
            // skip
            if (debug != null) {
                debug.println(e.getMessage());
            }
        }
    }

    private static class SecureRandomHolder {
        static final SecureRandom RANDOM = new SecureRandom();
    }

    public static SecureRandom getRandom() {
        return SecureRandomHolder.RANDOM;
    }

    public BGMJCEProvider() {
        super("BGMJCEProvider", 1.8d, "BGMJCEProvider");
    }

    @Override
    protected AbstractEntries createEntries(Provider provider) {
        return createJCEEntries(provider);
    }

    static AbstractEntries createJCEEntries(Provider provider) {
        return new BGMJCEEntries(provider);
    }
}
