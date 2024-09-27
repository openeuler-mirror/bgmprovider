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

package org.openeuler.sdf.wrapper.entity;


import org.openeuler.sdf.jca.commons.SDFUtil;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

public class SDFECCrefPublicKey {
    private int bits;
    private byte[] x;
    private byte[] y;

    public SDFECCrefPublicKey(ECPublicKey publicKey) {
        this.bits = publicKey.getParams().getCurve().getField().getFieldSize();
        ECPoint pubPoint = publicKey.getW();
        int size = (this.bits + 7) / 8;
        this.x = SDFUtil.asUnsignedByteArray(size, pubPoint.getAffineX());
        this.y = SDFUtil.asUnsignedByteArray(size, pubPoint.getAffineY());
    }

    public SDFECCrefPublicKey(int bits, byte[] x, byte[] y) {
        this.bits = bits;
        this.x = x;
        this.y = y;
    }

    public int getBits() {
        return bits;
    }

    public void setBits(int bits) {
        this.bits = bits;
    }

    public byte[] getX() {
        return x;
    }

    public void setX(byte[] x) {
        this.x = x;
    }

    public byte[] getY() {
        return y;
    }

    public void setY(byte[] y) {
        this.y = y;
    }
}
