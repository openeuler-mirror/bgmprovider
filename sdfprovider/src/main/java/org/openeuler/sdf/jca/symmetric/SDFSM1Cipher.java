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

package org.openeuler.sdf.jca.symmetric;

import org.openeuler.sdf.commons.constant.SDFDataKeyType;

/**
 * This class currently supports:
 * - SM1/ECB/NOPADDING
 * - SM1/ECB/PKCS5PADDING
 * - SM1/CBC/NOPADDING
 * - SM1/CBC/PKCS5PADDING
 * - SM1/CTR/NOPADDING
 * - SM1/XTS/NOPADDING
 * - SM1/GCM/NOPADDING
 */
abstract class SDFSM1Cipher extends SDFSymmetricCipherBase {
    public static final class SM1_ECB_NoPadding extends SDFSM1Cipher {
        public SM1_ECB_NoPadding() {
            super(SDFMode.ECB, SDFPadding.NOPADDING);
        }
    }

    public static final class SM1_CBC_NoPadding extends SDFSM1Cipher {
        public SM1_CBC_NoPadding() {
            super(SDFMode.CBC, SDFPadding.NOPADDING);
        }
    }

    public static final class SM1_ECB_PKCS5Padding extends SDFSM1Cipher {
        public SM1_ECB_PKCS5Padding() {
            super(SDFMode.ECB, SDFPadding.PKCS5PADDING);
        }
    }

    public static final class SM1_CBC_PKCS5Padding extends SDFSM1Cipher {
        public SM1_CBC_PKCS5Padding() {
            super(SDFMode.CBC, SDFPadding.PKCS5PADDING);
        }
    }

    public static final class SM1_CTR_NoPadding extends SDFSM1Cipher {
        public SM1_CTR_NoPadding() {
            super(SDFMode.CTR, SDFPadding.NOPADDING);
        }
    }

    public static final class SM1_XTS_NoPadding extends SDFSM1Cipher {
        public SM1_XTS_NoPadding() {
            super(SDFMode.XTS, SDFPadding.NOPADDING);
        }
    }

    public static final class SM1_GCM_NoPadding extends SDFSM1Cipher {
        public SM1_GCM_NoPadding() {
            super(SDFMode.GCM, SDFPadding.NOPADDING);
        }
    }

    SDFSM1Cipher(SDFMode mode, SDFPadding padding) {
        super(SDFDataKeyType.DATA_KEY_SM1, mode, padding, 16, 16);
    }
}
