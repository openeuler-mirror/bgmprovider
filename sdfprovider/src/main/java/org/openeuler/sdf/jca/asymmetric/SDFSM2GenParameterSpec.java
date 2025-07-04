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

package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.spec.SDFEncKeyGenParameterSpec;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;

import java.security.spec.ECGenParameterSpec;

public class SDFSM2GenParameterSpec extends ECGenParameterSpec implements SDFEncKeyGenParameterSpec {

    private final SDFKEKInfoEntity kekInfo;

    public SDFSM2GenParameterSpec(SDFKEKInfoEntity kekInfo, String stdName) {
        super(stdName);
        this.kekInfo = kekInfo;
    }

    /**
     * Creates a parameter specification for EC parameter
     * generation using a standard (or predefined) name
     * {@code stdName} in order to generate the corresponding
     * (precomputed) elliptic curve domain parameters. For the
     * list of supported names, please consult the documentation
     * of provider whose implementation will be used.
     *
     * @param kekId   SDF KekId used to generate the private key for encryption.
     * @param regionId   SDF KekId used to generate the private key for encryption.
     * @param cdpId   SDF KekId used to generate the private key for encryption.
     * @param pin   SDF KekId used to generate the private key for encryption.
     * @param stdName the standard name of the to-be-generated EC
     *                domain parameters.
     * @throws NullPointerException if {@code stdName}
     *                              is null.
     */
    public SDFSM2GenParameterSpec(byte[] kekId, byte[] regionId, byte[] cdpId, byte[] pin, String stdName) {
        this(new SDFKEKInfoEntity(kekId, regionId, cdpId, pin), stdName);
    }

    @Override
    public SDFKEKInfoEntity getKekInfo() {
        return kekInfo;
    }
}
