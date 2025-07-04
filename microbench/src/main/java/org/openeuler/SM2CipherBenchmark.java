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
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class SM2CipherBenchmark extends BaseBenchmark {

    private static final int SET_SIZE = 1024;
    private byte[][] data;
    int index = 0;

    @Param({"SM2"})
    private String algorithm;

    @Param({"256"})
    private int keyLength;

    @Param({"" + 1024,
            "" + 10 * 1024,
            "" + 100 * 1024,
            "" + 1024 * 1024})
    private int dataSize;

    private byte[][] encryptedData;
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    @Setup
    public void setUp() throws Exception {
        super.setUp();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2");
        if (super.sdfProviderFlag) {
            kpg.initialize(new SDFSM2GenParameterSpec(SDFKEKInfoEntity.getDefaultKEKInfo(), "sm2p256v1"));
        } else {
            kpg.initialize(keyLength);
        }
        KeyPair keyPair = kpg.generateKeyPair();

        encryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        decryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        data = fillRandom(new byte[SET_SIZE][dataSize]);
        encryptedData = fillEncrypted(data, encryptCipher);
    }

    @Benchmark
    public byte[] encrypt() throws IllegalBlockSizeException, BadPaddingException {
        byte[] d = data[index];
        index = (index + 1) % SET_SIZE;
        return encryptCipher.doFinal(d);
    }

    @Benchmark
    @Fork(jvmArgsAppend = {"-Djce.useLegacy=true"})
    public byte[] encryptLegacy() throws IllegalBlockSizeException, BadPaddingException {
        byte[] d = data[index];
        index = (index + 1) % SET_SIZE;
        return encryptCipher.doFinal(d);
    }

    @Benchmark
    public byte[] decrypt() throws IllegalBlockSizeException, BadPaddingException {
        byte[] e = encryptedData[index];
        index = (index + 1) % SET_SIZE;
        return decryptCipher.doFinal(e);
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public byte[] decryptLegacy() throws IllegalBlockSizeException, BadPaddingException {
        byte[] e = encryptedData[index];
        index = (index + 1) % SET_SIZE;
        return decryptCipher.doFinal(e);
    }

    private byte[][] fillEncrypted(byte[][] data, Cipher encryptCipher)
            throws IllegalBlockSizeException, BadPaddingException {
        byte[][] encryptedData = new byte[data.length][];
        for (int i = 0; i < encryptedData.length; i++) {
            encryptedData[i] = encryptCipher.doFinal(data[i]);
        }
        return encryptedData;
    }
}
