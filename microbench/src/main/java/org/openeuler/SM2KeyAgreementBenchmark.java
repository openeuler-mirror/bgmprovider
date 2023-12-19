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

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Setup;
import sun.security.util.ECUtil;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
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
        generateSecretLocalTest();
    }

    @Benchmark
    @Fork(jvmArgsAppend = {"-Djce.useLegacy=true"})
    public void generateSecretLocalLegacy() throws Exception {
        generateSecretLocalTest();
    }

    @Benchmark
    public void generateSecretPeer() throws Exception {
        generateSecretPeerTest();
    }

    @Benchmark
    @Fork(jvmArgsAppend = {"-Djce.useLegacy=true"})
    public void generateSecretPeerLegacy() throws Exception {
        generateSecretPeerTest();
    }

    @Benchmark
    public void generateSecretLocalAndPeer() throws Exception {
        generateSecretLocalAndPeerTest();
    }

    @Benchmark
    @Fork(jvmArgsAppend = {"-Djce.useLegacy=true"})
    public void generateSecretLocalAndPeerLegacy() throws Exception {
        generateSecretLocalAndPeerTest();
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

        byte[] localId = "1234567812345678".getBytes();
        BigInteger localRandom = SM2KeyExchangeUtil.generateRandom(
                localPublicKey.getParams().getOrder(), random);

        TestParam peerTestParam = peerTestParams[index];
        ECPublicKey peerPublicKey = peerTestParam.publicKey;
        byte[] peerId = "1234567812345678".getBytes();
        BigInteger peerRandom = SM2KeyExchangeUtil.generateRandom(
                peerPublicKey.getParams().getOrder(), random);
        ECPoint peerR = SM2KeyExchangeUtil.generateR(peerPublicKey, peerRandom);

        SM2KeyExchangeParameterSpec localParameterSpec = new SM2KeyExchangeParameterSpec(localPublicKey,
                localId, localRandom, ECUtil.encodePoint(peerR, peerPublicKey.getParams().getCurve()),
                peerId, secretLen, true);

        KeyAgreement localKeyAgreement = KeyAgreement.getInstance("SM2");
        localKeyAgreement.init(localPrivateKey, localParameterSpec, null);
        localKeyAgreement.doPhase(peerPublicKey, true);
        byte[] localSharedSecret = localKeyAgreement.generateSecret();
        index = index % SIZE;
        return localSharedSecret;
    }

    public byte[] generateSecretPeerTest() throws Exception {
        TestParam localTestParam = localTestParams[index];
        ECPublicKey localPublicKey = localTestParam.publicKey;
        byte[] localId = "1234567812345678".getBytes();
        BigInteger localRandom = SM2KeyExchangeUtil.generateRandom(
                localPublicKey.getParams().getOrder(), random);
        ECPoint localR = SM2KeyExchangeUtil.generateR(localPublicKey, localRandom);

        TestParam peerTestParam = peerTestParams[index];
        ECPrivateKey peerPrivateKey = peerTestParam.privateKey;
        ECPublicKey peerPublicKey = peerTestParam.publicKey;
        byte[] peerId = "1234567812345678".getBytes();
        BigInteger peerRandom = SM2KeyExchangeUtil.generateRandom(
                peerPublicKey.getParams().getOrder(), random);

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(peerPublicKey,
                peerId, peerRandom, ECUtil.encodePoint(localR, localPublicKey.getParams().getCurve()),
                localId, secretLen, false);

        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();
        index = index % SIZE;
        return peerSharedSecret;
    }
}
