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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.sun.security.util.ECNamedCurve;
import sun.security.util.ECKeySizeParameterSpec;
import sun.security.util.NamedCurve;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

public class ECParametersTest {
    private static NamedCurve nameCurve;

    private static ECNamedCurve ecNamedCurve;

    @BeforeClass
    public static void beforeClass() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Assert.assertTrue(keyPair.getPublic() instanceof ECPublicKey);
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        nameCurve = (NamedCurve) ecPublicKey.getParams();

        Security.insertProviderAt(new BGMJCEProvider(), 1);

        keyPairGenerator = KeyPairGenerator.getInstance("SM2");
        keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"));
        keyPair = keyPairGenerator.generateKeyPair();
        Assert.assertTrue(keyPair.getPublic() instanceof ECPublicKey);
        ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ecNamedCurve = (ECNamedCurve) ecPublicKey.getParams();
    }

    @Test
    public void initECGenParameterSpec() throws Exception {
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(new ECGenParameterSpec("sm2p256v1"));
        algorithmParameters.getParameterSpec(ECGenParameterSpec.class);
        algorithmParameters.getParameterSpec(ECParameterSpec.class);
        algorithmParameters.getParameterSpec(ECKeySizeParameterSpec.class);
    }

    @Test
    public void initECParameterSpec() throws Exception {
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(new ECParameterSpec(ecNamedCurve.getCurve(), ecNamedCurve.getGenerator(),
                ecNamedCurve.getOrder(), ecNamedCurve.getCofactor()));
        algorithmParameters.getParameterSpec(ECGenParameterSpec.class);
        algorithmParameters.getParameterSpec(ECParameterSpec.class);
        algorithmParameters.getParameterSpec(ECKeySizeParameterSpec.class);
    }

    @Test
    public void initECNameCurve() throws Exception {
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(ecNamedCurve);
        ECGenParameterSpec parameterSpec = algorithmParameters.getParameterSpec(ECGenParameterSpec.class);
        System.out.println(parameterSpec.getName());
        algorithmParameters.getParameterSpec(ECParameterSpec.class);
        algorithmParameters.getParameterSpec(ECKeySizeParameterSpec.class);
    }

    @Test
    public void initJDKNameCurve() throws Exception {
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(nameCurve);
        algorithmParameters.getParameterSpec(ECParameterSpec.class);
        algorithmParameters.getParameterSpec(ECKeySizeParameterSpec.class);
    }
}
