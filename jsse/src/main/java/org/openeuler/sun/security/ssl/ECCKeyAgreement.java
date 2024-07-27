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

import org.openeuler.spec.ECCPremasterSecretKeySpec;
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

    // creat need publicKey, decode need privateKey.
    private Key key;

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
        this.key = key;
        this.spec = (TlsECCKeyAgreementParameterSpec) params;
        this.random = random;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws IllegalStateException {
        throw new UnsupportedOperationException("ECCKeyAgreement not support engineDoPhase.");
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        throw new UnsupportedOperationException("ECCKeyAgreement.engineGenerateSecret not support the return byte[].");
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException {
        throw new UnsupportedOperationException("ECCKeyAgreement.engineGenerateSecret not support the return int.");
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] premasterSecret;
        byte[] encryptedKey;
        if (spec == null) {
            throw new IllegalStateException(
                    "ECCKeyAgreement.TlsECCKeyAgreementParameterSpec must be initialized");
        }
        try {
            if (spec.isClient()) {
                premasterSecret = generatePreMasterSecret(spec.getMajorVersion(), spec.getMinorVersion(), null);
                encryptedKey = encryptSecret(premasterSecret);
                return new ECCPremasterSecretKeySpec(premasterSecret,"TlsEccPremasterSecret", encryptedKey);
            }
            premasterSecret = decryptSecret();
            encryptedKey = spec.getEncryptedSecret();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e.getMessage(), e.getCause());
        }

        return new ECCPremasterSecretKeySpec(premasterSecret,"TlsEccPremasterSecret", encryptedKey);
    }

    private byte[] encryptSecret(byte[] premasterSecret) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (key == null) {
            throw new IllegalStateException(
                    "Key must be initialized");
        }
        if(!(key instanceof PublicKey)) {
            throw new IllegalStateException(
                    "decode need PublicKey");
        }
        Cipher cipher = JsseJce.getCipher(JsseJce.CIPHER_SM2);
        cipher.init(Cipher.ENCRYPT_MODE, key, random);
        return cipher.doFinal(premasterSecret);
    }

    private byte[] generatePreMasterSecret(int clientVersion, int serverVersion, byte[] encodedSecret) {
        if (encodedSecret == null) {
            if (random == null) {
                random = new SecureRandom();
            }
            encodedSecret = new byte[ECC_PREMASTER_KEY_LEN];
            random.nextBytes(encodedSecret);
        }
        encodedSecret[0] = (byte)clientVersion;
        encodedSecret[1] = (byte)serverVersion;

        return encodedSecret;
    }

    private byte[] decryptSecret() throws GeneralSecurityException {
        if (key == null) {
            throw new IllegalStateException(
                    "Key must be initialized");
        }
        if(!(key instanceof PrivateKey)) {
            throw new IllegalStateException(
                    "decode need PrivateKey");
        }
        if (spec.getEncryptedSecret() == null) {
            throw new IllegalStateException(
                    "TlsECCKeyAgreementParameterSpec.encryptedSecret must be initialized");
        }

        byte[] encoded = null;
        byte[] preMaster = null;
        Cipher cipher = JsseJce.getCipher(JsseJce.CIPHER_SM2);
        try {
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
            preMaster = generatePreMasterSecret(spec.getClientVersion(), spec.getServerVersion(), encoded);
        } catch (InvalidKeyException | UnsupportedOperationException iue) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.warning("The Cipher provider "
                        + safeProviderName(cipher)
                        + " caused exception: " + iue.getMessage());
            }
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
}
