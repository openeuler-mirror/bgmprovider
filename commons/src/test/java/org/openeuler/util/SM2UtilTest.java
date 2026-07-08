/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */
package org.openeuler.util;

import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class SM2UtilTest {

    @Test
    public void constructorAndPrivateInitializationHelpersWork() throws Exception {
        assertNotNull(new SM2Util());

        Method init = SM2Util.class.getDeclaredMethod("init");
        init.setAccessible(true);
        init.invoke(null);

        Field constructorField = SM2Util.class.getDeclaredField("BC_SM2PARAMETERSPEC_CONSTRUCTOR");
        constructorField.setAccessible(true);
        Object old = constructorField.get(null);
        try {
            constructorField.set(null, null);
            Method createBC = SM2Util.class.getDeclaredMethod("createBCSM2ParameterSpec", byte[].class);
            createBC.setAccessible(true);
            assertNull(createBC.invoke(null, new byte[]{1, 2, 3}));
        } finally {
            constructorField.set(null, old);
        }
    }

    @Test
    public void createSm2ParameterSpecCoversLegacyAndConstructorFailureBranches() throws Exception {
        Field useLegacy = ConfigUtil.class.getDeclaredField("useLegacyJCE");
        useLegacy.setAccessible(true);
        Field constructorField = SM2Util.class.getDeclaredField("BC_SM2PARAMETERSPEC_CONSTRUCTOR");
        constructorField.setAccessible(true);
        Method createBC = SM2Util.class.getDeclaredMethod("createBCSM2ParameterSpec", byte[].class);
        createBC.setAccessible(true);

        boolean oldUseLegacy = useLegacy.getBoolean(null);
        Object oldConstructor = constructorField.get(null);
        try {
            useLegacy.setBoolean(null, false);
            AlgorithmParameterSpec spec = SM2Util.createSM2ParameterSpec(new byte[]{1, 2});
            assertEquals("org.openeuler.org.bouncycastle.SM2ParameterSpec", spec.getClass().getName());

            useLegacy.setBoolean(null, true);
            constructorField.set(null,
                    Class.forName("org.bouncycastle.jcajce.spec.SM2ParameterSpec").getConstructor(byte[].class));
            assertEquals("org.bouncycastle.jcajce.spec.SM2ParameterSpec",
                    SM2Util.createSM2ParameterSpec(new byte[]{1, 2}).getClass().getName());

            Constructor<?> throwingConstructor = AbstractAlgorithmParameterSpec.class.getDeclaredConstructor();
            throwingConstructor.setAccessible(true);
            constructorField.set(null, throwingConstructor);
            assertNull(createBC.invoke(null, new byte[]{1, 2}));
        } finally {
            useLegacy.setBoolean(null, oldUseLegacy);
            constructorField.set(null, oldConstructor);
        }
    }

    private abstract static class AbstractAlgorithmParameterSpec implements AlgorithmParameterSpec {
        private AbstractAlgorithmParameterSpec() {
        }
    }
}
