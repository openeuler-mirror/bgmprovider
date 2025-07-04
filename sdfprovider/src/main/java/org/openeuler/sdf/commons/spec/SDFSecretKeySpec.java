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

import org.openeuler.sdf.commons.key.SDFEncryptKey;

import javax.crypto.spec.SecretKeySpec;

public class SDFSecretKeySpec extends SecretKeySpec implements SDFEncryptKey {
    private static final long serialVersionUID = 7166125660122475453L;

    // use enc key
    private boolean isEncKey = false;

    public SDFSecretKeySpec(byte[] key, String algorithm) {
        super(key, algorithm);
        this.isEncKey = false;
    }

    public SDFSecretKeySpec(byte[] key, String algorithm, boolean isEncKey) {
        super(key, algorithm);
        this.isEncKey = isEncKey;
    }

    @Override
    public boolean isEncKey() {
        return isEncKey;
    }
}
