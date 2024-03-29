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

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.*;

public class ECDHKeyAgreementTest {

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void test() throws NoSuchAlgorithmException, InvalidKeyException {
        // JDK 17 only support 256,384,512
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        KeyPairGenerator peerKeyPairGenerator = KeyPairGenerator.getInstance("EC");
        peerKeyPairGenerator.initialize(256);
        KeyPair peerKeyPair = peerKeyPairGenerator.generateKeyPair();

        // local
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init( keyPair.getPrivate());
        keyAgreement.doPhase(peerKeyPair.getPublic(), true);
        SecretKey preMasterSecret = keyAgreement.generateSecret("TlsPremasterSecret");

        // peer
        KeyAgreement peerPreMasterSecret = KeyAgreement.getInstance("ECDH");
        peerPreMasterSecret.init(peerKeyPair.getPrivate());
        peerPreMasterSecret.doPhase(keyPair.getPublic(), true);
        SecretKey peerPreMasterSecretKey = peerPreMasterSecret.generateSecret("TlsPremasterSecret");

        if (!preMasterSecret.equals(peerPreMasterSecretKey)) {
            throw new IllegalStateException("The TlsPremasterSecret keys generated by local and peer are not equal");
        }
    }
}
