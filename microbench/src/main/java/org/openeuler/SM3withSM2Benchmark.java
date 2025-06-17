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

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

public class SM3withSM2Benchmark extends BaseBenchmark {

    private static final int SET_SIZE = 1024;

    @Param({"SM3withSM2"})
    private String algorithm;

    @Param({"256"})
    private int keySize;

    @Param({"" + 1024,
            "" + 10 * 1024,
            "" + 100 * 1024,
            "" + 256 * 1024,
            "" + 1024 * 1024,
            "" + 10 * 1024 * 1024})
    private int dataSize;

    private byte[][] data;
    private int index = 0;
    private KeyPair keyPair;
    private Signature signature;
    private byte[][] sigData;
    private SecureRandom random;

    @Setup
    public void setup() throws Exception {
        super.setUp();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");
        if (sdfProviderFlag) {
            keyPairGenerator.initialize(
                    new SDFSM2GenParameterSpec(SDFKEKInfoEntity.getDefaultKEKInfo(), "sm2p256v1"));
        } else {
            keyPairGenerator.initialize(keySize);
        }

        keyPair = keyPairGenerator.generateKeyPair();
        data = new byte[SET_SIZE][dataSize];
        sigData = getSigBytes(data);

        signature = (provider != null) ?
                Signature.getInstance(algorithm, provider) :
                Signature.getInstance(algorithm);

        random = new SecureRandom();
    }

    private byte[][] getSigBytes(byte[][] data) throws Exception {
        byte[][] sigBytes = new byte[data.length][];
        Signature signature = provider != null ? Signature.getInstance(algorithm, provider) :
                Signature.getInstance(algorithm);
        signature.initSign(keyPair.getPrivate());
        for (int i = 0; i < sigBytes.length; i++) {
            signature.update(data[i]);
            sigBytes[i] = signature.sign();
        }
        return sigBytes;
    }

    @Benchmark
    public void sign() throws InvalidKeyException, SignatureException {
        testSign();
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public void signLegacy() throws InvalidKeyException, SignatureException {
        testSign();
    }

    public void testSign() throws InvalidKeyException, SignatureException{
        signature.initSign(keyPair.getPrivate());
        signature.update(data[index]);
        signature.sign();
        index = (index + 1) % SET_SIZE;
    }

    @Benchmark
    public void verify() throws InvalidKeyException, SignatureException {
        testVerify();
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public void verifyLegacy() throws InvalidKeyException, SignatureException {
        testVerify();
    }

    public void testVerify() throws InvalidKeyException, SignatureException {
        signature.initVerify(keyPair.getPublic());
        signature.update(data[index]);
        boolean verify = signature.verify(sigData[index]);
        if (!verify) {
            System.err.println("privateKey=" + Arrays.toString(keyPair.getPrivate().getEncoded()));
            System.err.println("publicKey=" + Arrays.toString(keyPair.getPublic().getEncoded()));
            System.out.println("data=" + Arrays.toString(data[index]));
            System.out.println("sigData=" + Arrays.toString(sigData[index]));
            throw new RuntimeException("verify failed");
        }
        index = (index + 1) % SET_SIZE;
    }

    @Benchmark
    public void signAndVerify() throws InvalidKeyException, SignatureException {

        index = (index + 1) % 10240;

        byte[] plainText = new byte[index];
        random.nextBytes(plainText);
        signature.initSign(keyPair.getPrivate());
        signature.update(plainText);
        byte[] signatureText = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.update(plainText);
        boolean verify = signature.verify(signatureText);
        if (!verify) {
            System.err.println("privateKey=" + Arrays.toString(keyPair.getPrivate().getEncoded()));
            System.err.println("publicKey=" + Arrays.toString(keyPair.getPublic().getEncoded()));
            System.out.println("data=" + Arrays.toString(plainText));
            System.out.println("sigData=" + Arrays.toString(signatureText));
            throw new RuntimeException("verify failed");
        }
    }
}
