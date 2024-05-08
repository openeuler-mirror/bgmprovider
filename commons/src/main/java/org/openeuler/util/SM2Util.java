/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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


package org.openeuler.util;

import org.openeuler.Config;
import org.openeuler.org.bouncycastle.SM2ParameterSpec;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.spec.AlgorithmParameterSpec;

public class SM2Util {
    private static final String BC_SM2PARAMETERSPEC_CLASS = "org.bouncycastle.jcajce.spec.SM2ParameterSpec";
    private static Constructor<?> BC_SM2PARAMETERSPEC_CONSTRUCTOR;

    static {
        try {
            init();
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            // skip
        }
    }

    private static void init() throws ClassNotFoundException, NoSuchMethodException {
        Class<?> clazz = Class.forName(BC_SM2PARAMETERSPEC_CLASS);
        BC_SM2PARAMETERSPEC_CONSTRUCTOR = clazz.getConstructor(byte[].class);
    }

    private static AlgorithmParameterSpec createBCSM2ParameterSpec(byte[] idBytes) {
        if (BC_SM2PARAMETERSPEC_CONSTRUCTOR == null) {
            return null;
        }
        try {
           return  (AlgorithmParameterSpec) BC_SM2PARAMETERSPEC_CONSTRUCTOR.newInstance((Object) idBytes);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
           // skip
        }
        return null;
    }

    public static AlgorithmParameterSpec createSM2ParameterSpec(byte[] idBytes) {
        return Config.useLegacyJCE() ?
                createBCSM2ParameterSpec(idBytes) :
                new SM2ParameterSpec(idBytes);
    }
}
