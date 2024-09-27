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

package org.openeuler.sdf.jca.random;

import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;

import java.security.SecureRandomSpi;

import org.openeuler.sdf.wrapper.SDFRandomNative;

public class SDFRandom extends SecureRandomSpi {

    @Override
    protected void engineSetSeed(byte[] seed) {
        // The encryption card does not require a seed.
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes.length > 0) {
            SDFSession session = SDFSessionManager.getInstance().getSession();
            try {
                SDFRandomNative.nativeGenerateRandom(session.getAddress(), bytes);
            }catch (Exception e){
                throw new RuntimeException("SDFRandom nativeGenerateRandom failed. random bytes length is "+ bytes.length, e);
            }finally {
                SDFSessionManager.getInstance().releaseSession(session);
            }
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        if (numBytes == 0) {
            return new byte[0];
        }
        byte[] seed = new byte[numBytes];
        engineNextBytes(seed);
        return seed;
    }
}