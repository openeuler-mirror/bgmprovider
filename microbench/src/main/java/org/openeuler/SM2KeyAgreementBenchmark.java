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

import org.openeuler.spec.SM2KeyExchangeParameterSpec;
import org.openjdk.jmh.annotations.*;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SM2KeyAgreementBenchmark extends BaseBenchmark {

    static class TestParam {
        private final ECPrivateKey privateKey;
        private final ECPublicKey publicKey;

        TestParam(ECPrivateKey privateKey, ECPublicKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        static TestParam[] generateTestParams(KeyPairGenerator keyPairGenerator) {
            // local
            KeyPair localKeyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey localPublicKey = (ECPublicKey) localKeyPair.getPublic();
            ECPrivateKey localPrivateKey = (ECPrivateKey) localKeyPair.getPrivate();

            // peer
            KeyPair peerKeyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
            ECPrivateKey peerPrivateKey = (ECPrivateKey) peerKeyPair.getPrivate();

            TestParam localTestParam = new TestParam(localPrivateKey, localPublicKey);
            TestParam peerTestParam = new TestParam(peerPrivateKey, peerPublicKey);
            return new TestParam[]{localTestParam, peerTestParam};
        }
    }

    private static final int SIZE = 1024;
    private static final SecureRandom random = new SecureRandom();
    private TestParam[] localTestParams;
    private TestParam[] peerTestParams;
    private int index = 0;
    private static final int secretLen = 48;

    @Setup
    public void setUp() throws Exception {
        super.setUp();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");
        localTestParams = new TestParam[SIZE];
        peerTestParams = new TestParam[SIZE];
        for (int i = 0; i < SIZE; i++) {
            TestParam[] testParams = TestParam.generateTestParams(keyPairGenerator);
            localTestParams[i] = testParams[0];
            peerTestParams[i] = testParams[1];
        }
    }

    @Benchmark
    public void generateSecretLocal() throws Exception {
        index = nextIndex(index);
        generateSecretLocalTest();
    }

    @Benchmark
    @Fork(jvmArgsAppend = {"-Djce.useLegacy=true"})
    public void generateSecretLocalLegacy() throws Exception {
        index = nextIndex(index);
        generateSecretLocalTest();
    }

    @Benchmark
    public void generateSecretPeer() throws Exception {
        index = nextIndex(index);
        generateSecretPeerTest();
    }

    @Benchmark
    @Fork(jvmArgsAppend = {"-Djce.useLegacy=true"})
    public void generateSecretPeerLegacy() throws Exception {
        index = nextIndex(index);
        generateSecretPeerTest();
    }

    @Benchmark
    public void generateSecretLocalAndPeer() throws Exception {
        index = nextIndex(index);
        generateSecretLocalAndPeerTest();
    }

    @Benchmark
    @Fork(jvmArgsAppend = {"-Djce.useLegacy=true"})
    public void generateSecretLocalAndPeerLegacy() throws Exception {
        index = nextIndex(index);
        generateSecretLocalAndPeerTest();
    }

    private int nextIndex(int index) {
        if (index - 4 < SIZE) {
            return index;
        }
        return 0;
    }

    public void generateSecretLocalAndPeerTest() throws Exception{
        byte[] localSharedSecret = generateSecretLocalTest();
        byte[] peerSharedSecret = generateSecretPeerTest();
        if (Arrays.equals(localSharedSecret, peerSharedSecret)) {
            System.err.println();
            throw new IllegalStateException("localSharedSecret and peerSharedSecret are not equal");
        }
    }

    public byte[] generateSecretLocalTest() throws Exception {
        TestParam localTestParam = localTestParams[index];
        ECPrivateKey localPrivateKey = localTestParam.privateKey;
        ECPublicKey localPublicKey = localTestParam.publicKey;

        TestParam localTmpTestParam = localTestParams[index + 1];
        ECPrivateKey localTmpPrivateKey = localTmpTestParam.privateKey;
        ECPublicKey localTmpPublicKey = localTmpTestParam.publicKey;
        byte[] localId = "1234567812345678".getBytes();

        TestParam peerTestParam = peerTestParams[index + 2];
        ECPublicKey peerPublicKey = peerTestParam.publicKey;

        TestParam peerTmpTestParam = peerTestParams[index + 3];
        ECPublicKey peerTmpPublicKey = peerTmpTestParam.publicKey;
        byte[] peerId = "1234567812345678".getBytes();

        AlgorithmParameterSpec localParameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTmpPrivateKey, localTmpPublicKey,
                peerId, peerTmpPublicKey, secretLen, false);

        KeyAgreement localKeyAgreement = KeyAgreement.getInstance("SM2");
        localKeyAgreement.init(localPrivateKey, localParameterSpec, random);
        localKeyAgreement.doPhase(peerPublicKey, true);
        return localKeyAgreement.generateSecret();
    }

    public byte[] generateSecretPeerTest() throws Exception {
        TestParam peerTestParam = peerTestParams[index];
        ECPrivateKey peerPrivateKey = peerTestParam.privateKey;
        ECPublicKey peerPublicKey = peerTestParam.publicKey;

        TestParam peerTmpTestParam = peerTestParams[index + 1];
        ECPrivateKey peerTmpPrivateKey = peerTmpTestParam.privateKey;
        ECPublicKey peerTmpPublicKey = peerTmpTestParam.publicKey;
        byte[] peerId = "1234567812345678".getBytes();

        TestParam localTestParam = localTestParams[index + 2];
        ECPublicKey localPublicKey = localTestParam.publicKey;

        TestParam localTmpTestParam = localTestParams[index + 3];
        ECPublicKey localTmpPublicKey = localTmpTestParam.publicKey;
        byte[] localId = "1234567812345678".getBytes();

        AlgorithmParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                peerId, peerPublicKey, peerTmpPrivateKey, peerTmpPublicKey,
                localId, localTmpPublicKey, secretLen, true);

        KeyAgreement localKeyAgreement = KeyAgreement.getInstance("SM2");
        localKeyAgreement.init(peerPrivateKey, peerParameterSpec, random);
        localKeyAgreement.doPhase(localPublicKey, true);
        return localKeyAgreement.generateSecret();
    }
}
