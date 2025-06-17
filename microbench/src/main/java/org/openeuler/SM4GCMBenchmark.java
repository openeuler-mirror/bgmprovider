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

package org.openeuler;

import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openeuler.sdf.jca.symmetric.SDFGCMParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;

public class SM4GCMBenchmark extends BaseBenchmark {

    private static final int SET_SIZE = 1024;
    private byte[][] data;
    private int index = 0;

    @Param({"SM4/GCM/NoPadding"})
    private String algorithm;

    @Param({"128"})
    private int keyLength;

    @Param({"" + 1024,
            "" + 10 * 1024,
            "" + 100 * 1024,
            "" + 1024 * 1024})
    private int dataSize;

    private byte[][] ivData;

    private byte[][] encryptedData;

    private Cipher decryptCipher;

    private SecretKey ks;

    private AlgorithmParameterSpec[] specs;

    @Setup
    public void setup() throws Exception {
        super.setUp();

        byte[] keyBytes = fillRandom(new byte[keyLength / 8]);
        if (sdfProviderFlag) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", provider);
            keyGenerator.init(new SDFKeyGeneratorParameterSpec(SDFKEKInfoEntity.getDefaultKEKInfo(), keyLength));
            ks = keyGenerator.generateKey();
        } else {
            ks = new SecretKeySpec(keyBytes, "SM4");
        }
        ivData = new byte[SET_SIZE][dataSize];
        data = fillRandom(new byte[SET_SIZE][dataSize]);
        encryptedData = new byte[SET_SIZE][dataSize];
        specs = new AlgorithmParameterSpec[SET_SIZE];
        fillEncrypted(data, ivData, encryptedData);
    }

    @Benchmark
    public void encrypt() throws Exception {
        encryptTest();
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public void encryptLegacy() throws Exception {
        encryptTest();
    }

    @Benchmark
    public void decrypt() throws Exception {
        decryptTest();
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public void decryptLegacy() throws Exception {
        decryptTest();
    }

    private void encryptTest() throws Exception {
        byte[] d = data[index];
        AlgorithmParameterSpec spec = specs[index];
        index = (index + 1) % SET_SIZE;
        Cipher encryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        encryptCipher.init(Cipher.ENCRYPT_MODE, ks, spec);
        encryptCipher.doFinal(d);
    }

    public byte[] decryptTest() throws Exception {
        byte[] e = encryptedData[index];
        AlgorithmParameterSpec spec = specs[index];
        index = (index + 1) % SET_SIZE;
        Cipher decryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        decryptCipher.init(Cipher.DECRYPT_MODE, ks, spec);
        return decryptCipher.doFinal(e);
    }


    private void fillEncrypted(byte[][] data, byte[][] ivData, byte[][] encryptedData)
            throws Exception {
        for (int i = 0; i < encryptedData.length; i++) {
            Cipher encryptCipher = (provider == null) ? Cipher.getInstance(algorithm)
                    : Cipher.getInstance(algorithm, provider);
            ivData[i] = fillRandom(new byte[16]);
            if (sdfProviderFlag) {
                specs[i] = new SDFGCMParameterSpec(keyLength, ivData[i]);
            } else {
                specs[i] = new IvParameterSpec(ivData[i]);
            }
            encryptCipher.init(Cipher.ENCRYPT_MODE, ks, specs[i]);
            encryptedData[i] = encryptCipher.doFinal(data[i]);
        }
    }
}
