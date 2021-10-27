/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.gm;

import org.openeuler.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static org.openeuler.gm.GMTlsUtil.*;

/**
 * KeyGenerator implementation for the GM TLS master secret derivation.
 *
 * @see org.openeuler.com.sun.crypto.provider.TlsKeyMaterialGenerator
 */
public class GMTlsKeyMaterialGenerator extends KeyGeneratorSpi {

    private final static String MSG = "GMTlsKeyMaterialGenerator must be "
            + "initialized using a TlsKeyMaterialParameterSpec";

    private TlsKeyMaterialParameterSpec spec;

    private int protocolVersion;

    public GMTlsKeyMaterialGenerator() {
    }

    @Override
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsKeyMaterialParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsKeyMaterialParameterSpec) params;
        if (!"RAW".equals(spec.getMasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException(
                    "Key format must be RAW");
        }
        protocolVersion = (spec.getMajorVersion() << 8)
                | spec.getMinorVersion();
        if (protocolVersion != 0x0101) {
            throw new InvalidAlgorithmParameterException(
                    "Only GM TLS 1.1 supported");
        }
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (spec == null) {
            throw new IllegalStateException(
                    "TlsKeyMaterialGenerator must be initialized");
        }
        try {
            return engineGenerateKey0();
        } catch (GeneralSecurityException e) {
            throw new ProviderException(e);
        }
    }

    private SecretKey engineGenerateKey0() throws GeneralSecurityException {
        byte[] masterSecret = spec.getMasterSecret().getEncoded();

        byte[] clientRandom = spec.getClientRandom();
        byte[] serverRandom = spec.getServerRandom();

        SecretKey clientMacKey = null;
        SecretKey serverMacKey = null;
        SecretKey clientCipherKey = null;
        SecretKey serverCipherKey = null;
        IvParameterSpec clientIv = null;
        IvParameterSpec serverIv = null;

        int macLength = spec.getMacKeyLength();
        int expandedKeyLength = spec.getExpandedCipherKeyLength();
        boolean isExportable = (expandedKeyLength != 0);
        int keyLength = spec.getCipherKeyLength();
        int ivLength = spec.getIvLength();

        int keyBlockLen = macLength + keyLength
                + (isExportable ? 0 : ivLength);
        keyBlockLen <<= 1;

        byte[] seed = concat(serverRandom, clientRandom);
        byte[] keyBlock = doGMTLS11PRF(masterSecret, LABEL_KEY_EXPANSION, seed,
                keyBlockLen, spec.getPRFHashAlg(),
                spec.getPRFHashLength(), spec.getPRFBlockSize());

        // partition keyblock into individual secrets
        int ofs = 0;
        if (macLength != 0) {
            byte[] tmp = new byte[macLength];

            // mac keys
            System.arraycopy(keyBlock, ofs, tmp, 0, macLength);
            ofs += macLength;
            clientMacKey = new SecretKeySpec(tmp, "Mac");

            System.arraycopy(keyBlock, ofs, tmp, 0, macLength);
            ofs += macLength;
            serverMacKey = new SecretKeySpec(tmp, "Mac");
        }

        if (keyLength == 0) { // SSL_RSA_WITH_NULL_* ciphersuites
            return new TlsKeyMaterialSpec(clientMacKey, serverMacKey);
        }

        String alg = spec.getCipherAlgorithm();

        if (!isExportable) {
            // cipher keys
            byte[] clientKeyBytes = new byte[keyLength];
            System.arraycopy(keyBlock, ofs, clientKeyBytes, 0, keyLength);
            ofs += keyLength;
            clientCipherKey = new SecretKeySpec(clientKeyBytes, alg);

            byte[] serverKeyBytes = new byte[keyLength];
            System.arraycopy(keyBlock, ofs, serverKeyBytes, 0, keyLength);
            ofs += keyLength;
            serverCipherKey = new SecretKeySpec(serverKeyBytes, alg);

            // IV keys if needed.
            if (ivLength != 0) {
                byte[] tmp = new byte[ivLength];

                System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
                ofs += ivLength;
                clientIv = new IvParameterSpec(tmp);

                System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
                serverIv = new IvParameterSpec(tmp);
            }
        }

        return new TlsKeyMaterialSpec(clientMacKey, serverMacKey,
                clientCipherKey, clientIv, serverCipherKey, serverIv);
    }
}
