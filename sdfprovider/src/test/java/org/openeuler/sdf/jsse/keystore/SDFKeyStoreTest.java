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

package org.openeuler.sdf.jsse.keystore;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJSSEProvider;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Objects;

public class SDFKeyStoreTest {
    // keystore type
    private static final String KEYSTORE_TYPE = "PKCS12";

    // keystore password
    private static final String KEYSTORE_PASSWORD = "12345678";

    // key aliases
    private static final String KEY_ENC_KEY_ALIASES = "server-enc-key";

    private static final String KEY_NORMAL_KEY_ALIASES = "server-normal-key";

    // key password
    private static final char[] KEY_PASSWORDS = "12345678".toCharArray();

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
        Security.insertProviderAt(new BGMJSSEProvider(), 2);
    }

    @Test
    public void test() throws Exception {
        testEncKeyStore();
    }

    public void testNormalKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        String keyStorePath = SDFTestUtil.getResource("server-normal-key.keystore");
        try (FileInputStream fileInputStream = new FileInputStream(Objects.requireNonNull(keyStorePath))) {
            keyStore.load(fileInputStream, KEYSTORE_PASSWORD.toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new KeyStoreException(e);
        }
        Key key = keyStore.getKey(KEY_NORMAL_KEY_ALIASES, KEY_PASSWORDS);
        if (key == null) {
            throw new KeyStoreException("The key aliased as " + KEY_NORMAL_KEY_ALIASES +
                    " does not exist in the " + keyStorePath);
        }
        if (!(key instanceof SDFECPrivateKeyImpl) || ((SDFECPrivateKeyImpl) key).isEncKey()) {
            throw new KeyStoreException("SDFProvider load normal keystore failed. The key aliased as " + KEY_NORMAL_KEY_ALIASES);
        }
    }

    public void testEncKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        String keyStorePath = SDFTestUtil.getResource("server-enc-key.keystore");
        try (FileInputStream fileInputStream = new FileInputStream(Objects.requireNonNull(keyStorePath))) {
            keyStore.load(fileInputStream, KEYSTORE_PASSWORD.toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new KeyStoreException(e);
        }
        Key key = keyStore.getKey(KEY_ENC_KEY_ALIASES, KEY_PASSWORDS);
        if (key == null) {
            throw new KeyStoreException("The key aliased as " + KEY_ENC_KEY_ALIASES +
                    " does not exist in the " + keyStorePath);
        }
        if (!(key instanceof SDFECPrivateKeyImpl) || !((SDFECPrivateKeyImpl) key).isEncKey()) {
            throw new KeyStoreException("SDFProvider load enc keystore failed. The key aliased as " + KEY_NORMAL_KEY_ALIASES);
        }
    }
}
