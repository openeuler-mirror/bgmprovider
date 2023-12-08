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

import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.sun.security.util.ECParameters;


import java.security.AlgorithmParameters;
import java.security.Security;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

public class AlgorithmParametersTest {

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMProvider(), 1);
    }

    @Test
    public void testGetAlgorithmParameters() throws Exception {
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec parameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
        ECParameters.getAlgorithmParameters(parameterSpec);
    }
}
