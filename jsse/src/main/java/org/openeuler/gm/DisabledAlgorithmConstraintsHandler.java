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

package org.openeuler.gm;

import sun.security.util.ConstraintsParameters;
import sun.security.util.Debug;
import sun.security.util.DisabledAlgorithmConstraints;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.util.Arrays;

public class DisabledAlgorithmConstraintsHandler {
    private static final Debug debug = Debug.getInstance("compatible");

    // Whether to use the method of higher version method
    private static boolean useHigherVersion = false;

    private static Method permitsMethod;

    static {
        init();
    }

    /**
     * JDK-8275887 adds a boolean parameter to the method permits(String, AlgorithmParameters, ConstraintsParameters).
     * For details, see <a href="https://bugs.openjdk.org/browse/JDK-8275887">JDK-8275887</a>
     */
    private static void init() {
        // get method permits(String,AlgorithmParameters,ConstraintsParameters)
        permitsMethod = getMethod("permits", new Class[]{String.class,
                AlgorithmParameters.class, ConstraintsParameters.class});
        if (permitsMethod != null) {
            return;
        }
        // get method permits(String,AlgorithmParameters,ConstraintsParameters,boolean)
        permitsMethod = getMethod("permits", new Class[]{String.class,
                AlgorithmParameters.class, ConstraintsParameters.class, boolean.class});
        if (permitsMethod != null) {
            useHigherVersion = true;
        }
    }

    private static Method getMethod(String name, Class<?>[] parameterTypes) {
        Method method = null;
        try {
            method = DisabledAlgorithmConstraints.class.getDeclaredMethod(name, parameterTypes);
            method.setAccessible(true);
            if (debug != null) {
                String params = Arrays.toString(parameterTypes);
                params = params.substring(1, params.length() - 1);
                debug.println("Try get method (" + params + ") success");
            }
        } catch (NoSuchMethodException e) {
            if (debug != null) {
                debug.println("NoSuchMethodException :" + e.getMessage());
            }
        }
        return method;
    }

    public static void permits(DisabledAlgorithmConstraints constraints, String algorithm, AlgorithmParameters ap,
                               ConstraintsParameters cp, boolean checkKey) {
        if (permitsMethod == null) {
            throw new IllegalStateException("permits(String,AlgorithmParameters,ConstraintsParameters) or permits" +
                    "(String,AlgorithmParameters,ConstraintsParameters,boolean) method not found");
        }
        try {
            if (useHigherVersion) {
                permitsMethod.invoke(constraints, algorithm, ap, cp, checkKey);
            } else {
                permitsMethod.invoke(constraints, algorithm, ap, cp);
            }
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }
}
