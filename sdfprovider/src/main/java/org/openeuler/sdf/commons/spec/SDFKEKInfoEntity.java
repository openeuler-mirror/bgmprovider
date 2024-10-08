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

package org.openeuler.sdf.commons.spec;

import org.openeuler.sdf.commons.config.SDFConfig;

import java.security.InvalidParameterException;

public class SDFKEKInfoEntity {
    private static SDFKEKInfoEntity defaultKEKInfo;

    static {
        initDefaultKEKInfo();
    }

    // KekId used to generate the secret key for encryption.
    protected byte[] kekId;

    // regionId used to generate the secret key for encryption.
    protected byte[] regionId;

    // cdpID used to generate the secret key for encryption.
    protected byte[] cdpId;

    // PIN used to generate the secret key for encryption.
    protected byte[] PIN;

    public SDFKEKInfoEntity(byte[] kekId, byte[] regionId, byte[] cdpId, byte[] PIN) {
        if (kekId == null || kekId.length != 32){
            throw new InvalidParameterException("Wrong kekId size: must be equal to 32");
        }
        if (regionId == null && cdpId == null) {
            throw new InvalidParameterException("Both cdpID and regionId cannot be empty.");
        }
        this.kekId = kekId;
        this.regionId = regionId;
        this.cdpId = cdpId;
        this.PIN = PIN;
    }

    private static void initDefaultKEKInfo() {
        SDFConfig config = SDFConfig.getInstance();
        if(config.isUseEncDEK() && !config.getDefaultKEKId().isEmpty()) {
            defaultKEKInfo = new SDFKEKInfoEntity(config.getDefaultKEKId().getBytes(),
                    config.getDefaultRegionId().getBytes(),
                    config.getDefaultCdpId().getBytes(),
                    config.getDefaultPin().getBytes());
        }
    }

    public static SDFKEKInfoEntity getDefaultKEKInfo() {
        return defaultKEKInfo;
    }

    public byte[] getKekId() {
        return kekId;
    }

    public byte[] getRegionId() {
        return regionId;
    }

    public byte[] getCdpId() {
        return cdpId;
    }

    public byte[] getPIN() {
        return PIN;
    }
}