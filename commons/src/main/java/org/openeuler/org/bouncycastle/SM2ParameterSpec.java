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

package org.openeuler.org.bouncycastle;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * Parameter spec for SM2 ID parameter
 */
public class SM2ParameterSpec implements AlgorithmParameterSpec {
    private byte[] id;

    private ECParameterSpec params;

    /**
     * Return the ID value.
     *
     * @return the ID string.
     */
    public byte[] getId() {
        return id == null ? null : id.clone();
    }

    public ECParameterSpec getParams() {
        return params;
    }

    /**
     * Base constructor.
     *
     * @param id the ID string associated with this usage of SM2.
     */
    public SM2ParameterSpec(byte[] id) {
        this(id, null);
    }

    public SM2ParameterSpec(byte[] id, ECParameterSpec params) {
        if (id == null) {
            throw new NullPointerException("id string cannot be null");
        }
        this.id = id;
        this.params = params;
    }
}
