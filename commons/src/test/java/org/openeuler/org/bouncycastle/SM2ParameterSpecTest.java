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
package org.openeuler.org.bouncycastle;

import org.junit.Test;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static org.junit.Assert.*;

public class SM2ParameterSpecTest {

    @Test
    public void clonesIdOnAccessAndKeepsParamsReference() {
        byte[] id = new byte[]{1, 2, 3};
        ECParameterSpec params = new ECParameterSpec(
                new EllipticCurve(new ECFieldFp(BigInteger.valueOf(23)), BigInteger.ONE, BigInteger.ONE),
                new ECPoint(BigInteger.valueOf(3), BigInteger.valueOf(10)),
                BigInteger.valueOf(7),
                1);

        SM2ParameterSpec spec = new SM2ParameterSpec(id, params);
        id[0] = 9;
        assertArrayEquals(new byte[]{9, 2, 3}, spec.getId());
        assertSame(params, spec.getParams());

        byte[] copy = spec.getId();
        copy[1] = 9;
        assertArrayEquals(new byte[]{9, 2, 3}, spec.getId());
    }

    @Test
    public void getIdReturnsNullWhenFieldIsNull() throws Exception {
        SM2ParameterSpec spec = new SM2ParameterSpec(new byte[]{1});
        java.lang.reflect.Field id = SM2ParameterSpec.class.getDeclaredField("id");
        id.setAccessible(true);
        id.set(spec, null);
        assertNull(spec.getId());
    }

    @Test(expected = NullPointerException.class)
    public void rejectsNullId() {
        new SM2ParameterSpec(null);
    }
}
