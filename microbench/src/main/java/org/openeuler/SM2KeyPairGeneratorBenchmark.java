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

import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.jca.asymmetric.SDFSM2GenParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Setup;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class SM2KeyPairGeneratorBenchmark extends BaseBenchmark {

    private KeyPairGenerator keyPairGenerator;

    @Setup
    public void setUp() throws Exception {
        super.setUp();
        try {
            keyPairGenerator = (provider == null) ?
                    KeyPairGenerator.getInstance("SM2") :
                    KeyPairGenerator.getInstance("SM2", provider);
            if (sdfProviderFlag) {
                keyPairGenerator.initialize(
                        new SDFSM2GenParameterSpec(SDFKEKInfoEntity.getDefaultKEKInfo(), "sm2p256v1"));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    public void generateKeyPair() {
        keyPairGenerator.generateKeyPair();
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public void generateKeyPairLegacy() {
        keyPairGenerator.generateKeyPair();
    }
}
