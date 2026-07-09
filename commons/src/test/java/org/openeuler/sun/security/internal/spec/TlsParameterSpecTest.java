/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */
package org.openeuler.sun.security.internal.spec;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;

import static org.junit.Assert.*;

@SuppressWarnings("deprecation")
public class TlsParameterSpecTest {

    private static SecretKey key(String algorithm) {
        return new SecretKeySpec(new byte[]{1, 2, 3, 4}, algorithm);
    }

    @Test
    public void tlsKeyMaterialSpecExposesAllKeyParts() {
        SecretKey clientMac = key("HmacSHA256");
        SecretKey serverMac = key("HmacSHA384");
        SecretKey clientCipher = key("AES");
        SecretKey serverCipher = key("SM4");
        IvParameterSpec clientIv = new IvParameterSpec(new byte[]{1});
        IvParameterSpec serverIv = new IvParameterSpec(new byte[]{2});

        TlsKeyMaterialSpec macOnly = new TlsKeyMaterialSpec(clientMac, serverMac);
        assertSame(clientMac, macOnly.getClientMacKey());
        assertSame(serverMac, macOnly.getServerMacKey());
        assertNull(macOnly.getClientCipherKey());
        assertNull(macOnly.getServerCipherKey());

        TlsKeyMaterialSpec withCiphers = new TlsKeyMaterialSpec(clientMac, serverMac, clientCipher, serverCipher);
        assertSame(clientCipher, withCiphers.getClientCipherKey());
        assertSame(serverCipher, withCiphers.getServerCipherKey());

        TlsKeyMaterialSpec full = new TlsKeyMaterialSpec(
                clientMac, serverMac, clientCipher, clientIv, serverCipher, serverIv);
        assertEquals("TlsKeyMaterial", full.getAlgorithm());
        assertNull(full.getFormat());
        assertNull(full.getEncoded());
        assertSame(clientIv, full.getClientIv());
        assertSame(serverIv, full.getServerIv());
    }

    @Test
    public void tlsMasterSecretSpecClonesArraysAndAcceptsNullSessionHash() {
        byte[] clientRandom = new byte[]{1, 2};
        byte[] serverRandom = new byte[]{3, 4};
        TlsMasterSecretParameterSpec spec = new TlsMasterSecretParameterSpec(
                key("TlsPremasterSecret"), 3, 3, clientRandom, serverRandom, "SHA-256", 32, 64);

        clientRandom[0] = 9;
        serverRandom[0] = 9;
        assertArrayEquals(new byte[]{1, 2}, spec.getClientRandom());
        assertArrayEquals(new byte[]{3, 4}, spec.getServerRandom());
        assertEquals(3, spec.getMajorVersion());
        assertEquals(3, spec.getMinorVersion());
        assertEquals("SHA-256", spec.getPRFHashAlg());
        assertEquals(32, spec.getPRFHashLength());
        assertEquals(64, spec.getPRFBlockSize());
        assertSame(spec.getPremasterSecret(), spec.getPremasterSecret());

        byte[] copy = spec.getClientRandom();
        copy[1] = 9;
        assertArrayEquals(new byte[]{1, 2}, spec.getClientRandom());

        TlsMasterSecretParameterSpec nullHash = new TlsMasterSecretParameterSpec(
                key("TlsPremasterSecret"), 3, 4, (byte[]) null, "SHA-384", 48, 128);
        assertArrayEquals(new byte[0], nullHash.getExtendedMasterSecretSessionHash());
    }

    @Test
    public void tlsMasterSecretSpecClonesSessionHash() {
        byte[] hash = new byte[]{7, 8};
        TlsMasterSecretParameterSpec spec = new TlsMasterSecretParameterSpec(
                key("TlsPremasterSecret"), 3, 4, hash, "SHA-384", 48, 128);
        hash[0] = 1;
        assertArrayEquals(new byte[]{7, 8}, spec.getExtendedMasterSecretSessionHash());
        byte[] copy = spec.getExtendedMasterSecretSessionHash();
        copy[1] = 1;
        assertArrayEquals(new byte[]{7, 8}, spec.getExtendedMasterSecretSessionHash());
    }

    @Test(expected = NullPointerException.class)
    public void tlsMasterSecretRejectsNullPremasterSecret() {
        new TlsMasterSecretParameterSpec(null, 3, 3, new byte[0], new byte[0], "SHA-256", 32, 64);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsMasterSecretRejectsNegativeVersion() {
        new TlsMasterSecretParameterSpec(key("TlsPremasterSecret"), -1, 3, new byte[0], new byte[0],
                "SHA-256", 32, 64);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsMasterSecretRejectsTooLargeVersion() {
        new TlsMasterSecretParameterSpec(key("TlsPremasterSecret"), 3, 256, new byte[0], new byte[0],
                "SHA-256", 32, 64);
    }

    @Test
    public void tlsKeyMaterialParameterSpecValidatesAndClonesInputs() {
        byte[] clientRandom = new byte[]{1};
        byte[] serverRandom = new byte[]{2};
        TlsKeyMaterialParameterSpec spec = new TlsKeyMaterialParameterSpec(
                key("TlsMasterSecret"), 3, 1, clientRandom, serverRandom, "AES",
                16, 40, 12, 32, "SHA-256", 32, 64);
        clientRandom[0] = 9;
        serverRandom[0] = 9;

        assertSame(spec.getMasterSecret(), spec.getMasterSecret());
        assertEquals(3, spec.getMajorVersion());
        assertEquals(1, spec.getMinorVersion());
        assertArrayEquals(new byte[]{1}, spec.getClientRandom());
        assertArrayEquals(new byte[]{2}, spec.getServerRandom());
        assertEquals("AES", spec.getCipherAlgorithm());
        assertEquals(16, spec.getCipherKeyLength());
        assertEquals(40, spec.getExpandedCipherKeyLength());
        assertEquals(12, spec.getIvLength());
        assertEquals(32, spec.getMacKeyLength());
        assertEquals("SHA-256", spec.getPRFHashAlg());
        assertEquals(32, spec.getPRFHashLength());
        assertEquals(64, spec.getPRFBlockSize());

        TlsKeyMaterialParameterSpec tls11 = new TlsKeyMaterialParameterSpec(
                key("TlsMasterSecret"), 3, 2, new byte[0], new byte[0], "AES",
                16, 40, 12, 32, "SHA-256", 32, 64);
        assertEquals(0, tls11.getExpandedCipherKeyLength());

        TlsKeyMaterialParameterSpec ssl3 = new TlsKeyMaterialParameterSpec(
                key("TlsMasterSecret"), 2, 2, new byte[0], new byte[0], "AES",
                16, 40, 12, 32, "SHA-256", 32, 64);
        assertEquals(40, ssl3.getExpandedCipherKeyLength());
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsKeyMaterialRejectsWrongMasterSecretAlgorithm() {
        new TlsKeyMaterialParameterSpec(key("RAW"), 3, 3, new byte[0], new byte[0],
                "AES", 16, 0, 12, 32, "SHA-256", 32, 64);
    }

    @Test(expected = NullPointerException.class)
    public void tlsKeyMaterialRejectsNullCipherAlgorithm() {
        new TlsKeyMaterialParameterSpec(key("TlsMasterSecret"), 3, 3, new byte[0], new byte[0],
                null, 16, 0, 12, 32, "SHA-256", 32, 64);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsKeyMaterialRejectsNegativeLengths() {
        new TlsKeyMaterialParameterSpec(key("TlsMasterSecret"), 3, 3, new byte[0], new byte[0],
                "AES", -1, 0, 12, 32, "SHA-256", 32, 64);
    }

    @Test
    public void tlsPrfParameterSpecClonesSeedAndAllowsNullSecret() {
        byte[] seed = new byte[]{1, 2};
        TlsPrfParameterSpec spec = new TlsPrfParameterSpec(null, "label", seed, 16, "SHA-256", 32, 64);
        seed[0] = 9;
        assertNull(spec.getSecret());
        assertEquals("label", spec.getLabel());
        assertArrayEquals(new byte[]{1, 2}, spec.getSeed());
        assertEquals(16, spec.getOutputLength());
        assertEquals("SHA-256", spec.getPRFHashAlg());
        assertEquals(32, spec.getPRFHashLength());
        assertEquals(64, spec.getPRFBlockSize());

        byte[] copy = spec.getSeed();
        copy[1] = 9;
        assertArrayEquals(new byte[]{1, 2}, spec.getSeed());
    }

    @Test(expected = NullPointerException.class)
    public void tlsPrfRejectsNullLabel() {
        new TlsPrfParameterSpec(null, null, new byte[0], 1, "SHA-256", 32, 64);
    }

    @Test(expected = NullPointerException.class)
    public void tlsPrfRejectsNullSeed() {
        new TlsPrfParameterSpec(null, "label", null, 1, "SHA-256", 32, 64);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsPrfRejectsNonPositiveOutputLength() {
        new TlsPrfParameterSpec(null, "label", new byte[0], 0, "SHA-256", 32, 64);
    }

    @Test
    public void tlsEccKeyAgreementSpecCoversVersionsAndEncryptedSecret() {
        TlsECCKeyAgreementParameterSpec oldClient = new TlsECCKeyAgreementParameterSpec(0x0301, 0x0303);
        assertEquals(0x03, oldClient.getMajorVersion());
        assertEquals(0x03, oldClient.getMinorVersion());
        assertNull(oldClient.getEncryptedSecret());
        assertTrue(oldClient.isClient());

        byte[] encrypted = new byte[]{1, 2, 3};
        TlsECCKeyAgreementParameterSpec newClient = new TlsECCKeyAgreementParameterSpec(0x0303, 0x0301, encrypted);
        encrypted[0] = 9;
        assertEquals(0x03, newClient.getMajorVersion());
        assertEquals(0x03, newClient.getMinorVersion());
        assertArrayEquals(new byte[]{1, 2, 3}, newClient.getEncryptedSecret());
        byte[] copy = newClient.getEncryptedSecret();
        copy[1] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, newClient.getEncryptedSecret());

        TlsECCKeyAgreementParameterSpec server = new TlsECCKeyAgreementParameterSpec(new byte[]{4}, 0x0303, 0x0303, false);
        assertFalse(server.isClient());
        assertEquals(0x0303, server.getClientVersion());
        assertEquals(0x0303, server.getServerVersion());

        TlsECCKeyAgreementParameterSpec oldNegotiated = new TlsECCKeyAgreementParameterSpec(0x0301, 0x0201);
        assertEquals(0x02, oldNegotiated.getMajorVersion());
        assertEquals(0x01, oldNegotiated.getMinorVersion());
    }

    @Test
    public void tlsEccFixPropertyBranchesAreCoveredInIsolatedLoaders() throws Exception {
        assertIsolatedTlsEccVersion("true", 0x03, 0x01);
        assertIsolatedTlsEccVersion("TRUE", 0x03, 0x01);
        assertIsolatedTlsEccVersion("false", 0x02, 0x01);
    }

    private static void assertIsolatedTlsEccVersion(String property, int major, int minor) throws Exception {
        String old = System.getProperty("com.sun.net.ssl.eccPreMasterSecretFix");
        try {
            System.setProperty("com.sun.net.ssl.eccPreMasterSecretFix", property);
            URLClassLoader loader = new URLClassLoader(new URL[]{Paths.get("target", "classes").toUri().toURL()}, null);
            try {
                Class<?> clazz = Class.forName(
                        "org.openeuler.sun.security.internal.spec.TlsECCKeyAgreementParameterSpec", true, loader);
                Constructor<?> constructor = clazz.getConstructor(int.class, int.class);
                Object spec = constructor.newInstance(0x0301, 0x0201);
                assertEquals(Integer.valueOf(major), clazz.getDeclaredMethod("getMajorVersion").invoke(spec));
                assertEquals(Integer.valueOf(minor), clazz.getDeclaredMethod("getMinorVersion").invoke(spec));
            } finally {
                loader.close();
            }
        } finally {
            if (old == null) {
                System.clearProperty("com.sun.net.ssl.eccPreMasterSecretFix");
            } else {
                System.setProperty("com.sun.net.ssl.eccPreMasterSecretFix", old);
            }
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsEccRejectsNullEncryptedSecret() {
        new TlsECCKeyAgreementParameterSpec(0x0303, 0x0303, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsEccServerConstructorRejectsNullEncryptedSecret() {
        new TlsECCKeyAgreementParameterSpec(null, 0x0303, 0x0303, false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsEccRejectsNegativeVersion() {
        new TlsECCKeyAgreementParameterSpec(-1, 0x0303);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tlsEccRejectsTooLargeVersion() {
        new TlsECCKeyAgreementParameterSpec(0x0303, 0x10000);
    }
}
