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

package org.openeuler.sun.security.ssl;

import org.openeuler.sun.security.internal.spec.TlsECCKeyAgreementParameterSpec;
import sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;
import sun.security.util.KeyUtil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class ECCKeyAgreement extends KeyAgreementSpi {

    private final static String MSG = "ECCKeyAgreement must be "
            + "initialized using a TlsECCKeyAgreementParameterSpec";

    private TlsECCKeyAgreementParameterSpec spec;

    private SecureRandom random;

    private PrivateKey key;

    private static final int ECC_PREMASTER_KEY_LEN = 48;

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        throw new UnsupportedOperationException(MSG);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(params instanceof TlsECCKeyAgreementParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.key = (PrivateKey) key;
        this.spec = (TlsECCKeyAgreementParameterSpec) params;
        this.random = random;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws IllegalStateException {
        throw new UnsupportedOperationException("ECCKeyAgreement not support engineDoPhase.");
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (spec == null) {
            throw new IllegalStateException(
                    "ECCKeyAgreement.TlsECCKeyAgreementParameterSpec must be initialized");
        }
        if (spec.isClient()) {
            return creat();
        }
        try {
            return decode();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e.getMessage(), e.getCause());
        }
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, ShortBufferException {
        if (offset + ECC_PREMASTER_KEY_LEN > sharedSecret.length) {
            throw new ShortBufferException("Need " + ECC_PREMASTER_KEY_LEN
                    + " bytes, only " + (sharedSecret.length - offset)
                    + " available");
        }
        byte[] secret = engineGenerateSecret();
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        return new SecretKeySpec(engineGenerateSecret(),"TlsEccPremasterSecret");
    }

    private byte[] creat() {
        byte[] b = spec.getEncryptedSecret();
        if (b == null) {
            if (random == null) {
                random = new SecureRandom();
            }
            b = new byte[ECC_PREMASTER_KEY_LEN];
            random.nextBytes(b);
        }
        b[0] = (byte)spec.getMajorVersion();
        b[1] = (byte)spec.getMinorVersion();

        return b;
    }

    private byte[] decode() throws GeneralSecurityException {
        if (key == null) {
            throw new IllegalStateException(
                    "PrivateKey must be initialized");
        }
        if (spec.getEncryptedSecret() == null) {
            throw new IllegalStateException(
                    "TlsECCKeyAgreementParameterSpec.encryptedSecret must be initialized");
        }

        byte[] encoded = null;
        boolean needFailover = false;
        Cipher cipher = JsseJce.getCipher(JsseJce.CIPHER_SM2);
        try {
            // Try UNWRAP_MODE mode firstly.
            cipher.init(Cipher.UNWRAP_MODE, key,
                    spec,
                    random);

            // The provider selection can be delayed, please don't call
            // any Cipher method before the call to Cipher.init().
            String providerName = cipher.getProvider().getName();
            needFailover = !(KeyUtil.isOracleJCEProvider(
                    providerName) || providerName.equals("BGMJCEProvider"));
        } catch (InvalidKeyException | UnsupportedOperationException | InvalidAlgorithmParameterException iue) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.warning("The Cipher provider "
                        + safeProviderName(cipher)
                        + " caused exception: " + iue.getMessage());
            }

            needFailover = true;
        }

        byte[] preMaster;
        if (needFailover) {
            // The cipher might be spoiled by unsuccessful call to init(),
            // so request a fresh instance
            cipher = JsseJce.getCipher(JsseJce.CIPHER_SM2);

            // Use DECRYPT_MODE and dispose the previous initialization.
            cipher.init(Cipher.DECRYPT_MODE, key);
            boolean failed = false;
            try {
                encoded = cipher.doFinal(spec.getEncryptedSecret());
            } catch (BadPaddingException bpe) {
                // Note: encoded == null
                failed = true;
            }
            encoded = KeyUtil.checkTlsPreMasterSecretKey(
                    spec.getClientVersion(), spec.getServerVersion(),
                    random, encoded, failed);
            preMaster = generatePremasterSecret(encoded);
        } else {
            // the cipher should have been initialized
            preMaster = cipher.unwrap(spec.getEncryptedSecret(),
                    "TlsEccPremasterSecret", Cipher.SECRET_KEY).getEncoded();
        }
        return preMaster;
    }

    /*
     * Retrieving the cipher's provider name for the debug purposes
     * can throw an exception by itself.
     */
    private static String safeProviderName(Cipher cipher) {
        try {
            return cipher.getProvider().toString();
        } catch (Exception e) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Retrieving The Cipher provider name" +
                        " caused exception ", e);
            }
        }
        try {
            return cipher.toString() + " (provider name not available)";
        } catch (Exception e) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Retrieving The Cipher name" +
                        " caused exception ", e);
            }
        }

        return "(cipher/provider names not available)";
    }

    // generate a premaster secret with the specified version number
    @SuppressWarnings("deprecation")
    private byte[] generatePremasterSecret(byte[] encodedSecret) throws GeneralSecurityException {

        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
            SSLLogger.fine("Generating a premaster secret");
        }

        try {
            // ProtocolVersion.TLS12.id : 0x0303
            String s = ((spec.getClientVersion() >= 0x0303) ?
                    "SunTls12RsaPremasterSecret" : "SunTlsRsaPremasterSecret");
            KeyGenerator kg = JsseJce.getKeyGenerator(s);
            kg.init(new TlsRsaPremasterSecretParameterSpec(
                            spec.getClientVersion(), spec.getServerVersion(), encodedSecret),
                    random);
            return kg.generateKey().getEncoded();
        } catch (InvalidAlgorithmParameterException |
                NoSuchAlgorithmException iae) {
            // unlikely to happen, otherwise, must be a provider exception
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("ECC premaster secret generation error:");
                iae.printStackTrace(System.out);
            }

            throw new GeneralSecurityException(
                    "Could not generate premaster secret", iae);
        }
    }
}
