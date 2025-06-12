/*
 * Copyright (c) 2005, 2017, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.sdf.jsse;

import org.openeuler.sdf.wrapper.SDFPRFNative;
import org.openeuler.sun.security.internal.spec.TlsMasterSecretParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static org.openeuler.sdf.jsse.commons.SDFGMTlsConstant.LABEL_MASTER_SECRET;


/**
 * KeyGenerator implementation for the GM TLS master secret derivation.
 *
 * @see org.openeuler.com.sun.crypto.provider.TlsMasterSecretGenerator
 */
public class SDFGMTlsMasterSecretGenerator extends KeyGeneratorSpi {
    private final static String MSG = "SDFGMTlsMasterSecretGenerator must be "
            + "initialized using a TlsMasterSecretParameterSpec";

    private TlsMasterSecretParameterSpec spec;

    private int protocolVersion;

    public SDFGMTlsMasterSecretGenerator() {
    }

    @Override
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params,
                              SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsMasterSecretParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsMasterSecretParameterSpec) params;
        if (!"RAW".equals(spec.getPremasterSecret().getFormat())) {
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
                    "GMTlsMasterSecretGenerator must be initialized");
        }
        if (spec.getExtendedMasterSecretSessionHash().length != 0) {
            throw new RuntimeException("Not supported extended master secret");
        }
        SecretKey premasterKey = spec.getPremasterSecret();
        byte[] premaster = premasterKey.getEncoded();

        int premasterMajor, premasterMinor;
        if (premasterKey.getAlgorithm().equals("GmTlsEccPremasterSecret")) {
            // RSA
            premasterMajor = premaster[0] & 0xff;
            premasterMinor = premaster[1] & 0xff;
        } else {
            // DH, KRB5, others
            premasterMajor = -1;
            premasterMinor = -1;
        }

        byte[] clientRandom = spec.getClientRandom();
        byte[] serverRandom = spec.getServerRandom();
        String prfHashAlg = spec.getPRFHashAlg();
        // GMTls masterSecret size is fixed 48 Bytes. Native methods return is encrypted masterSecret.
        byte[] master = SDFPRFNative.nativeGMTLSPRF(prfHashAlg, null, premaster, LABEL_MASTER_SECRET,
                clientRandom, serverRandom, null, 0, 0, 0);
        return new SDFGMTlsMasterSecretKey(master, premasterMajor,
                premasterMinor, true);

    }
}
