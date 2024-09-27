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

package org.openeuler.sdf.jsse;

import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.wrapper.SDFPRFNative;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialSpec;
import org.openeuler.sdf.wrapper.entity.SDFKeyPrfParameter;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static org.openeuler.sdf.jsse.commons.SDFGMTlsConstant.*;
import static org.openeuler.sdf.commons.constant.SDFConstant.ENC_FIXED_KEY_SIZE;

/**
 * KeyGenerator implementation for the GM TLS master secret derivation.
 *
 * @see org.openeuler.com.sun.crypto.provider.TlsKeyMaterialGenerator
 */
public class SDFGMTlsKeyMaterialGenerator extends KeyGeneratorSpi {

    private final static String MSG = "SDFGMTlsKeyMaterialGenerator must be "
            + "initialized using a TlsKeyMaterialParameterSpec";

    private TlsKeyMaterialParameterSpec spec;

    private int protocolVersion;

    public SDFGMTlsKeyMaterialGenerator() {
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
        if (protocolVersion != 0x0101 && protocolVersion != 0x0303) {
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
        int macLength = spec.getMacKeyLength();
        int keyLength = spec.getCipherKeyLength();
        int ivLength = spec.getIvLength();

        SecretKey clientMacKey = null;
        SecretKey serverMacKey = null;
        SecretKey clientCipherKey = null;
        SecretKey serverCipherKey = null;
        IvParameterSpec clientIv = null;
        IvParameterSpec serverIv = null;

        // extended master secret
        int expandedKeyLength = spec.getExpandedCipherKeyLength();
        boolean isExportable = (expandedKeyLength != 0);
        if (isExportable) {
            throw new RuntimeException("Not supported extended Cipher Key");
        }

        // get keyBlock
        SDFSession session = SDFSessionManager.getInstance().getSession();
        byte[] keyBlock;
        try {
            keyBlock = SDFPRFNative.nativeGMTLSPRF(session.getAddress(), masterSecret, LABEL_KEY_EXPANSION,
                    clientRandom, serverRandom, new SDFKeyPrfParameter(keyLength, ivLength, macLength), null, null);
        } finally {
            SDFSessionManager.getInstance().releaseSession(session);
        }

        // partition keyblock into individual secrets
        int ofs = 0;
        if (macLength != 0) {
            byte[] tmp = new byte[ENC_FIXED_KEY_SIZE];

            // mac keys
            System.arraycopy(keyBlock, ofs, tmp, 0, ENC_FIXED_KEY_SIZE);
            ofs += ENC_FIXED_KEY_SIZE;
            clientMacKey = new SDFSecretKeySpec(tmp, "Mac", true);

            System.arraycopy(keyBlock, ofs, tmp, 0, ENC_FIXED_KEY_SIZE);
            ofs += ENC_FIXED_KEY_SIZE;
            serverMacKey = new SDFSecretKeySpec(tmp, "Mac", true);
        }

        String alg = spec.getCipherAlgorithm();

        // cipher keys
        byte[] clientKeyBytes = new byte[ENC_FIXED_KEY_SIZE];
        System.arraycopy(keyBlock, ofs, clientKeyBytes, 0, ENC_FIXED_KEY_SIZE);
        ofs += ENC_FIXED_KEY_SIZE;
        clientCipherKey = new SDFSecretKeySpec(clientKeyBytes, alg, true);

        byte[] serverKeyBytes = new byte[ENC_FIXED_KEY_SIZE];
        System.arraycopy(keyBlock, ofs, serverKeyBytes, 0, ENC_FIXED_KEY_SIZE);
        ofs += ENC_FIXED_KEY_SIZE;
        serverCipherKey = new SDFSecretKeySpec(serverKeyBytes, alg, true);

        // IV keys if needed.
        if (ivLength != 0) {
            byte[] tmp = new byte[ivLength];

            System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
            ofs += ivLength;
            clientIv = new IvParameterSpec(tmp);

            System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
            serverIv = new IvParameterSpec(tmp);
        }

        return new TlsKeyMaterialSpec(clientMacKey, serverMacKey,
                clientCipherKey, clientIv, serverCipherKey, serverIv);
    }
}
