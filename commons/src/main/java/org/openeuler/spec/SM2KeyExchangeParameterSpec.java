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

package org.openeuler.spec;

import org.openeuler.constant.GMConstants;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SM2KeyExchangeParameterSpec
 */
public class SM2KeyExchangeParameterSpec implements AlgorithmParameterSpec {
    // local id
    private byte[] localId;
    // local public key
    private ECPublicKey localPublicKey;
    // local temp private key (local random)
    private ECPrivateKey localTempPrivateKey;
    // local temp private key (local random)
    private ECPublicKey localTempPublicKey;

    // peer id
    private byte[] peerId;
    // peer temp public key (R point)
    private ECPublicKey peerTempPublicKey;

    // length of the secret to be derived
    private int secretLen;

    // use client mode
    private boolean useClientMode;

    // When the PublicKey can be obtained locally, it is recommended to use this constructor


    public SM2KeyExchangeParameterSpec(byte[] localId, ECPublicKey localPublicKey,
                                       ECPrivateKey localTempPrivateKey, ECPublicKey localTempPublicKey,
                                       byte[] peerId, ECPublicKey peerTempPublicKey,
                                       int secretLen, boolean useClientMode) {
        this.localId = localId;
        this.localPublicKey = localPublicKey;
        this.localTempPrivateKey = localTempPrivateKey;
        this.localTempPublicKey = localTempPublicKey;
        this.peerId = peerId;
        this.peerTempPublicKey = peerTempPublicKey;
        this.secretLen = secretLen;
        this.useClientMode = useClientMode;
    }

    public SM2KeyExchangeParameterSpec(ECPublicKey localPublicKey,
                                       ECPrivateKey localTempPrivateKey, ECPublicKey localTempPublicKey,
                                       ECPublicKey peerTempPublicKey,
                                       int secretLen, boolean useClientMode) {

        this(GMConstants.DEFAULT_ID, localPublicKey, localTempPrivateKey, localTempPublicKey,
                GMConstants.DEFAULT_ID, peerTempPublicKey, secretLen, useClientMode);
    }

    public SM2KeyExchangeParameterSpec(byte[] localId,
                                       ECPrivateKey localTempPrivateKey, ECPublicKey localTempPublicKey,
                                       byte[] peerId, ECPublicKey peerTempPublicKey,
                                       int secretLen, boolean useClientMode) {
        this(localId, null, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, useClientMode);
    }

    public byte[] getLocalId() {
        return localId;
    }

    public void setLocalId(byte[] localId) {
        this.localId = localId;
    }

    public ECPublicKey getLocalPublicKey() {
        return localPublicKey;
    }

    public void setLocalPublicKey(ECPublicKey localPublicKey) {
        this.localPublicKey = localPublicKey;
    }

    public ECPrivateKey getLocalTempPrivateKey() {
        return localTempPrivateKey;
    }

    public void setLocalTempPrivateKey(ECPrivateKey localTempPrivateKey) {
        this.localTempPrivateKey = localTempPrivateKey;
    }

    public ECPublicKey getLocalTempPublicKey() {
        return localTempPublicKey;
    }

    public void setLocalTempPublicKey(ECPublicKey localTempPublicKey) {
        this.localTempPublicKey = localTempPublicKey;
    }

    public byte[] getPeerId() {
        return peerId;
    }

    public void setPeerId(byte[] peerId) {
        this.peerId = peerId;
    }

    public ECPublicKey getPeerTempPublicKey() {
        return peerTempPublicKey;
    }

    public void setPeerTempPublicKey(ECPublicKey peerTempPublicKey) {
        this.peerTempPublicKey = peerTempPublicKey;
    }

    public int getSecretLen() {
        return secretLen;
    }

    public void setSecretLen(int secretLen) {
        this.secretLen = secretLen;
    }

    public boolean isUseClientMode() {
        return useClientMode;
    }

    public void setUseClientMode(boolean useClientMode) {
        this.useClientMode = useClientMode;
    }
}
