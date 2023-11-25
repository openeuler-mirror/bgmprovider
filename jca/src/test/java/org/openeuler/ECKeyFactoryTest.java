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

package org.openeuler;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECKeyFactoryTest {

    /**
     * openssl ecparam -genkey -name SM2 -out sm2_private_key.pem -outform PEM
     * openssl pkcs8 -topk8 -in sm2_private_key.pem -out sm2_private_key_pkcs8.pem  -nocrypt
     * openssl ec -in sm2_private_key.pem -pubout -out sm2_public_key.pem -outform PEM
     */
    private static final String PRIVATE_KEY_PKCS8_OPENSSL3 =
            "MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIBAFgCWSCQiG3Hi4" +
            "Nb1dNZHD4nXazp0YHJdieAxbemLYoUQDQgAEaWliarKKK7X1NTb3M40bxbxM7PoJ" +
            "7evQh7sn2iku5R6M5G4gqNeLYzmwd4PToIFGtf9yjNcHdnU5KMvkHcBp4w==";

    private static final String PRIVATE_KEY_PKCS8_OPENSSL1 =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgC/i+/DxJs4Bx7lj8" +
            "HsodiyRYRpJV5mOZ0mNhySPApy6hRANCAAQaKi5Xwz9S4Z/ggDQ0Gfn2CS0+ZbHe" +
            "0jaayUUj10GXmhcl3jBVtjxpIUuTRZEEj1Lx4BSYawdvQJaubs+R0LEr";

    private static final String PUBLIC_KEY_X509_OPENSSL3 =
            "MFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABGlpYmqyiiu19TU29zONG8W8TOz6" +
            "Ce3r0Ie7J9opLuUejORuIKjXi2M5sHeD06CBRrX/cozXB3Z1OSjL5B3AaeM=";

    private static final String PUBLIC_KEY_X509_OPENSSL1 =
            "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEGiouV8M/UuGf4IA0NBn59gktPmWx" +
            "3tI2mslFI9dBl5oXJd4wVbY8aSFLk0WRBI9S8eAUmGsHb0CWrm7PkdCxKw==";

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void generatePrivate() throws Exception {
        if (!BGMJCEConfig.useLegacy()) {
            generatePrivate(PRIVATE_KEY_PKCS8_OPENSSL3);
        }
        generatePrivate(PRIVATE_KEY_PKCS8_OPENSSL1);
    }


    @Test
    public void generatePublic() throws Exception {
        if (!BGMJCEConfig.useLegacy()) {
            generatePublic(PUBLIC_KEY_X509_OPENSSL3);
        }
        generatePublic(PUBLIC_KEY_X509_OPENSSL1);
    }

    private void generatePrivate(String privateKeyStr) throws Exception {
        byte[] decodeBytes = Base64.getDecoder().decode(privateKeyStr.getBytes());
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodeBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new IllegalStateException("Illegal SM2 private key");
        }
    }

    private void generatePublic(String publicKeyStr)  throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        byte[] decodeBytes = Base64.getDecoder().decode(publicKeyStr.getBytes());
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decodeBytes);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalStateException("Illegal SM2 public key");
        }
    }
}
