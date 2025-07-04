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
import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class SM4Benchmark extends BaseBenchmark {

    private static final int SET_SIZE = 1024;
    private byte[][] data;
    private int index = 0;

    @Param({"SM4/ECB/NoPadding", "SM4/ECB/PKCS5Padding",
            "SM4/CBC/NoPadding", "SM4/CBC/PKCS5Padding",
            "SM4/CTR/NoPadding",
            "SM4/OFB/NoPadding", "SM4/OFB/PKCS5Padding",
            "SM4/CCM/NoPadding",
            "SM4/OCB/NoPadding",
            "SM4/CFB/NoPadding","SM4/CFB/PKCS5Padding",
            "SM4/CTS/NoPadding"
            // "SM4/CTS/PKCS5Padding"
    })
    private String algorithm;

    @Param("SM4")
    private String keyAlgorithm;

    @Param({"128"})
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
    public void setup() throws Exception {
        super.setUp();

        SecretKey ks = generateKey(keyAlgorithm);

        encryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        encryptCipher.init(Cipher.ENCRYPT_MODE, ks);
        decryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        decryptCipher.init(Cipher.DECRYPT_MODE, ks, encryptCipher.getParameters());

        data = fillRandom(new byte[SET_SIZE][dataSize]);
        encryptedData = fillEncrypted(data, encryptCipher);
    }

    private SecretKey generateKey(String keyAlgorithm)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
        if (sdfProviderFlag) {
            keyGenerator.init(new SDFKeyGeneratorParameterSpec(SDFKEKInfoEntity.getDefaultKEKInfo(), keyLength));
        } else {
            keyGenerator.init(keyLength);
        }
        return keyGenerator.generateKey();
    }

    @Benchmark
    public byte[] encrypt() throws IllegalBlockSizeException, BadPaddingException {
        byte[] d = data[index];
        index = (index + 1) % SET_SIZE;
        return encryptCipher.doFinal(d);
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
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
