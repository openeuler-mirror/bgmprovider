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
package org.openeuler.spec;

import org.junit.Test;
import org.openeuler.constant.GMConstants;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static org.junit.Assert.*;

public class CommonSpecTest {

    @Test
    public void eccPremasterSecretConstructorsExposeExpectedState() {
        byte[] key = new byte[]{1, 2, 3, 4};
        byte[] encrypted = new byte[]{5, 6};

        ECCPremasterSecretKeySpec withEncrypted = new ECCPremasterSecretKeySpec(key, "GMTLS", encrypted);
        assertEquals("GMTLS", withEncrypted.getAlgorithm());
        assertArrayEquals(key, withEncrypted.getEncoded());
        assertSame(encrypted, withEncrypted.getEncryptedKey());

        ECCPremasterSecretKeySpec withoutEncrypted = new ECCPremasterSecretKeySpec(key, "GMTLS");
        assertNull(withoutEncrypted.getEncryptedKey());

        ECCPremasterSecretKeySpec slice = new ECCPremasterSecretKeySpec(key, 1, 2, "GMTLS");
        assertArrayEquals(new byte[]{2, 3}, slice.getEncoded());
    }

    @Test
    public void sm2KeyExchangeConstructorsAndSettersRoundTripValues() {
        SM2KeyExchangeParameterSpec defaultIds = new SM2KeyExchangeParameterSpec(
                null, null, null, null, 32, true);
        assertArrayEquals(GMConstants.DEFAULT_ID, defaultIds.getLocalId());
        assertArrayEquals(GMConstants.DEFAULT_ID, defaultIds.getPeerId());
        assertEquals(32, defaultIds.getSecretLen());
        assertTrue(defaultIds.isUseClientMode());

        byte[] localId = new byte[]{1};
        byte[] peerId = new byte[]{2};
        SM2KeyExchangeParameterSpec spec = new SM2KeyExchangeParameterSpec(
                localId, null, null, null, peerId, null, 48, false);
        assertSame(localId, spec.getLocalId());
        assertSame(peerId, spec.getPeerId());

        byte[] newLocalId = new byte[]{3};
        byte[] newPeerId = new byte[]{4};
        spec.setLocalId(newLocalId);
        spec.setPeerId(newPeerId);
        spec.setLocalPublicKey(null);
        spec.setLocalTempPrivateKey(null);
        spec.setLocalTempPublicKey(null);
        spec.setPeerTempPublicKey(null);
        spec.setSecretLen(16);
        spec.setUseClientMode(true);

        assertSame(newLocalId, spec.getLocalId());
        assertSame(newPeerId, spec.getPeerId());
        assertNull(spec.getLocalPublicKey());
        assertNull(spec.getLocalTempPrivateKey());
        assertNull(spec.getLocalTempPublicKey());
        assertNull(spec.getPeerTempPublicKey());
        assertEquals(16, spec.getSecretLen());
        assertTrue(spec.isUseClientMode());
    }

    @Test
    public void secretKeySpecStillDefensivelyCopiesKeyMaterial() {
        byte[] key = new byte[]{9, 8, 7};
        ECCPremasterSecretKeySpec spec = new ECCPremasterSecretKeySpec(key, "RAW");
        key[0] = 1;
        assertArrayEquals(new byte[]{9, 8, 7}, spec.getEncoded());
        byte[] encoded = spec.getEncoded();
        encoded[1] = 1;
        assertArrayEquals(new byte[]{9, 8, 7}, spec.getEncoded());
        assertTrue(Arrays.equals(new SecretKeySpec(new byte[]{9, 8, 7}, "RAW").getEncoded(), spec.getEncoded()));
    }
}
