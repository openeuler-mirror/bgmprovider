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

package org.openeuler.SM2;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SM2KeyExchangeParameterSpec
 */
public class SM2KeyExchangeParameterSpec implements AlgorithmParameterSpec {
    // local public key
    private PublicKey localPublicKey;

    // local id
    private byte[] localId;

    // local random
    private BigInteger localRandom;

    // peer R point
    private byte[] peerRBytes;

    // peer id
    private byte[] peerId;

    // length of the secret to be derived
    private int secretLen;

    // use client mode
    private boolean useClientMode;

    // When the PublicKey can be obtained locally, it is recommended to use this constructor
    public SM2KeyExchangeParameterSpec(PublicKey localPublicKey, byte[] localId,
                                       BigInteger localRandom, byte[] peerRBytes, byte[] peerId,
                                       int secretLen, boolean useClientMode) {
        this.localPublicKey = localPublicKey;
        this.localId = localId;
        this.localRandom = localRandom;
        this.peerRBytes = peerRBytes;
        this.peerId = peerId;
        this.secretLen = secretLen;
        this.useClientMode = useClientMode;
    }

    // When there is only a private key locally, a public key can be generated based on the private key
    public SM2KeyExchangeParameterSpec(byte[] localId, BigInteger localRandom,
                                       byte[] peerRBytes, byte[] peerId, int secretLen, boolean useClientMode) {
        this(null, localId, localRandom, peerRBytes, peerId, secretLen, useClientMode);
    }

    public PublicKey getLocalPublicKey() {
        return localPublicKey;
    }

    public byte[] getLocalId() {
        return localId;
    }

    public BigInteger getLocalRandom() {
        return localRandom;
    }

    public byte[] getPeerRBytes() {
        return peerRBytes;
    }

    public byte[] getPeerId() {
        return peerId;
    }

    public int getSecretLen() {
        return secretLen;
    }

    public boolean isUseClientMode() {
        return useClientMode;
    }
}
