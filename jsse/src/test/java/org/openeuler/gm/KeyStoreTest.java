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

import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;

public class KeyStoreTest extends BaseTest {
    // keystore type
    private static final String KEYSTORE_TYPE = "PKCS12";

    // keystore password
    private static final String KEYSTORE_PASSWORD = "12345678";

    // key aliases
    private static final String[] KEY_ALIASES = new String[]{
            "server-rsa",
            "server-ec",
            "server-sm2-sig",
            "server-sm2-enc",
    };

    // key password
    private static final String[] KEY_PASSWORDS = new String[]{
            "rsa12345678",
            "ec12345678",
            "sm2sig12345678",
            "sm2enc12345678",
    };

    @Test
    public void testDiffKeyStorePassAndKeyPass() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        String keyStorePath = TestUtils.getPath("server-diff-pass.keystore");
        try (FileInputStream fileInputStream = new FileInputStream(Objects.requireNonNull(keyStorePath))) {
            keyStore.load(fileInputStream, KEYSTORE_PASSWORD.toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new KeyStoreException(e);
        }

        try {
            for (int i = 0; i < KEY_ALIASES.length; i++) {
                Key key = keyStore.getKey(KEY_ALIASES[i], KEY_PASSWORDS[i].toCharArray());
                if (key == null) {
                    throw new KeyStoreException("The key aliased as " + KEY_ALIASES[i] +
                            " does not exist in the " + keyStorePath);
                }
            }
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new KeyStoreException(e);
        }
    }
}
