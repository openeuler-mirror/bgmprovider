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

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

/**
 * GM TLS util
 */
public class GMTlsUtil {
    private final static byte[] B0 = new byte[0];

    final static byte[] LABEL_MASTER_SECRET = // "master secret"
            {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};

    final static byte[] LABEL_EXTENDED_MASTER_SECRET =
            // "extended master secret"
            {101, 120, 116, 101, 110, 100, 101, 100, 32, 109, 97, 115, 116,
                    101, 114, 32, 115, 101, 99, 114, 101, 116};

    final static byte[] LABEL_KEY_EXPANSION = // "key expansion"
            {107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};

    final static byte[] LABEL_CLIENT_WRITE_KEY = // "client write key"
            {99, 108, 105, 101, 110, 116, 32, 119, 114, 105, 116, 101, 32,
                    107, 101, 121};

    final static byte[] LABEL_SERVER_WRITE_KEY = // "server write key"
            {115, 101, 114, 118, 101, 114, 32, 119, 114, 105, 116, 101, 32,
                    107, 101, 121};

    final static byte[] LABEL_IV_BLOCK = // "IV block"
            {73, 86, 32, 98, 108, 111, 99, 107};

    /*
     * TLS HMAC "inner" and "outer" padding.  This isn't a function
     * of the digest algorithm.
     */
    private static final byte[] HMAC_ipad64 = genPad((byte) 0x36, 64);
    private static final byte[] HMAC_ipad128 = genPad((byte) 0x36, 128);
    private static final byte[] HMAC_opad64 = genPad((byte) 0x5c, 64);
    private static final byte[] HMAC_opad128 = genPad((byte) 0x5c, 128);

    static byte[] genPad(byte b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    static byte[] concat(byte[] b1, byte[] b2) {
        int n1 = b1.length;
        int n2 = b2.length;
        byte[] b = new byte[n1 + n2];
        System.arraycopy(b1, 0, b, 0, n1);
        System.arraycopy(b2, 0, b, n1, n2);
        return b;
    }

    static byte[] doGMTLS11PRF(byte[] secret, byte[] labelBytes,
                               byte[] seed, int outputLength,
                               String prfHash, int prfHashLength, int prfBlockSize)
            throws NoSuchAlgorithmException, DigestException {
        if (prfHash == null) {
            throw new NoSuchAlgorithmException("Unspecified PRF algorithm");
        }
        MessageDigest prfMD = MessageDigest.getInstance(prfHash);
        return doGMTLS11PRF(secret, labelBytes, seed, outputLength,
                prfMD, prfHashLength, prfBlockSize);
    }

    static byte[] doGMTLS11PRF(byte[] secret, byte[] labelBytes,
                               byte[] seed, int outputLength,
                               MessageDigest mdPRF, int mdPRFLen, int mdPRFBlockSize)
            throws DigestException {

        if (secret == null) {
            secret = B0;
        }

        // If we have a long secret, digest it first.
        if (secret.length > mdPRFBlockSize) {
            secret = mdPRF.digest(secret);
        }

        byte[] output = new byte[outputLength];
        byte[] ipad;
        byte[] opad;

        switch (mdPRFBlockSize) {
            case 64:
                ipad = HMAC_ipad64.clone();
                opad = HMAC_opad64.clone();
                break;
            case 128:
                ipad = HMAC_ipad128.clone();
                opad = HMAC_opad128.clone();
                break;
            default:
                throw new DigestException("Unexpected block size.");
        }

        // P_HASH(Secret, label + seed)
        expand(mdPRF, mdPRFLen, secret, 0, secret.length, labelBytes,
                seed, output, ipad, opad);

        return output;
    }

    /*
     * @param digest the MessageDigest to produce the HMAC
     * @param hmacSize the HMAC size
     * @param secret the secret
     * @param secOff the offset into the secret
     * @param secLen the secret length
     * @param label the label
     * @param seed the seed
     * @param output the output array
     */
    private static void expand(MessageDigest digest, int hmacSize,
                               byte[] secret, int secOff, int secLen, byte[] label, byte[] seed,
                               byte[] output, byte[] pad1, byte[] pad2) throws DigestException {
        /*
         * modify the padding used, by XORing the key into our copy of that
         * padding.  That's to avoid doing that for each HMAC computation.
         */
        for (int i = 0; i < secLen; i++) {
            pad1[i] ^= secret[i + secOff];
            pad2[i] ^= secret[i + secOff];
        }

        byte[] tmp = new byte[hmacSize];
        byte[] aBytes = null;

        /*
         * compute:
         *
         *     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
         *                            HMAC_hash(secret, A(2) + seed) +
         *                            HMAC_hash(secret, A(3) + seed) + ...
         * A() is defined as:
         *
         *     A(0) = seed
         *     A(i) = HMAC_hash(secret, A(i-1))
         */
        int remaining = output.length;
        int ofs = 0;
        while (remaining > 0) {
            /*
             * compute A() ...
             */
            // inner digest
            digest.update(pad1);
            if (aBytes == null) {
                digest.update(label);
                digest.update(seed);
            } else {
                digest.update(aBytes);
            }
            digest.digest(tmp, 0, hmacSize);

            // outer digest
            digest.update(pad2);
            digest.update(tmp);
            if (aBytes == null) {
                aBytes = new byte[hmacSize];
            }
            digest.digest(aBytes, 0, hmacSize);

            /*
             * compute HMAC_hash() ...
             */
            // inner digest
            digest.update(pad1);
            digest.update(aBytes);
            digest.update(label);
            digest.update(seed);
            digest.digest(tmp, 0, hmacSize);

            // outer digest
            digest.update(pad2);
            digest.update(tmp);
            digest.digest(tmp, 0, hmacSize);

            int k = Math.min(hmacSize, remaining);
            for (int i = 0; i < k; i++) {
                output[ofs++] ^= tmp[i];
            }
            remaining -= k;
        }
    }

    /*
     * Determine whether it is an invalid EC certificate.
     */
    public static boolean isInvalidECCert(String keyType, String sigAlgName) {
        // If the keyType is EC, filter the certificate of the signature algorithm SM3withSM2.
        return keyType.equals(GMConstants.EC) && GMConstants.equalsAlgorithm(
                GMConstants.SM3_WITH_SM2, sigAlgName);
    }

    /*
     * Determine whether it is an invalid SM2 certificate.
     */
    public static boolean isInvalidSM2Cert(String keyType, String sigAlgName) {
        return keyType.equals(GMConstants.SM2) && !GMConstants.equalsAlgorithm(
                GMConstants.SM3_WITH_SM2, sigAlgName);
    }

    /*
     * Determine whether it is an invalid EC or SM2 certificate.
     */
    public static boolean isInvalidECOrSM2Cert(String keyType, String sigAlgName) {
        return isInvalidECCert(keyType, sigAlgName) || isInvalidSM2Cert(keyType, sigAlgName);
    }

    /**
     * Copy source keystore to dest keystore.
     * @param srcKeyStore Source keystore
     * @param srcStorePassword Source keystore password
     * @param destKeyStore Dest keystore
     * @param destStorePassword  Dest keystore password
     */
    public static void copyKeyStore(KeyStore srcKeyStore, char[] srcStorePassword,
                                     KeyStore destKeyStore , char[] destStorePassword)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        for (Enumeration<String> e = srcKeyStore.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();
            if (srcKeyStore.isCertificateEntry(alias)) {
                Certificate cert = srcKeyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    destKeyStore.setCertificateEntry(alias, cert);
                }
            } else if (srcKeyStore.isKeyEntry(alias)) {
                Certificate[] certs = srcKeyStore.getCertificateChain(alias);
                if ((certs != null) && (certs.length > 0) &&
                        (certs[0] instanceof X509Certificate)) {
                    Key key = srcKeyStore.getKey(alias, srcStorePassword);
                    destKeyStore.setKeyEntry(alias, key, destStorePassword, certs);
                }
            }
        }
    }
}
