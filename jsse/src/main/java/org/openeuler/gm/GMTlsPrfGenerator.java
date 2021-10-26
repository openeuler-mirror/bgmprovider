/*
 * Copyright (c) 2005, 2017, Oracle and/or its affiliates. All rights reserved.
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

package org.openeuler.gm;

import org.openeuler.sun.security.internal.spec.TlsPrfParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static org.openeuler.gm.GMTlsUtil.doGMTLS11PRF;

/**
 * KeyGenerator implementation for the GM TLS PRF function.
 *
 * @see org.openeuler.com.sun.crypto.provider.TlsPrfGenerator
 */
public class GMTlsPrfGenerator extends KeyGeneratorSpi {
    private final static String MSG = "TlsPrfGenerator must be "
            + "initialized using a TlsPrfParameterSpec";

    private TlsPrfParameterSpec spec;

    public GMTlsPrfGenerator() {
    }

    @Override
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsPrfParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsPrfParameterSpec) params;
        SecretKey key = spec.getSecret();
        if ((key != null) && (!"RAW".equals(key.getFormat()))) {
            throw new InvalidAlgorithmParameterException(
                    "Key encoding format must be RAW");
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
                    "GMTlsPrfGenerator must be initialized");
        }
        SecretKey key = spec.getSecret();
        byte[] secret = (key == null) ? null : key.getEncoded();
        try {
            byte[] labelBytes = spec.getLabel().getBytes("UTF8");
            int n = spec.getOutputLength();
            byte[] prfBytes = doGMTLS11PRF(secret, labelBytes, spec.getSeed(), n,
                    spec.getPRFHashAlg(), spec.getPRFHashLength(),
                    spec.getPRFBlockSize());
            return new SecretKeySpec(prfBytes, "GMTlsPrf");
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            throw new ProviderException("Could not generate PRF", e);
        }
    }
}
