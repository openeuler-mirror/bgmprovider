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
import org.openeuler.sdf.jca.commons.SDFKeyUtil;

import java.security.InvalidKeyException;

/**
 * This class currently supports:
 * - AES/ECB/NOPADDING
 * - AES/ECB/PKCS5PADDING
 * - AES/CBC/NOPADDING
 * - AES/CBC/PKCS5PADDING
 * - AES/XTS/NOPADDING
 * - AES/GCM/NOPADDING
 */
abstract class SDFAESCipher extends SDFSymmetricCipherBase {

    public static final class AES_ECB_NoPadding extends SDFAESCipher {
        public AES_ECB_NoPadding() {
            super(SDFMode.ECB, SDFPadding.NOPADDING, -1);
        }
    }
    public static final class AES_ECB_PKCS5Padding extends SDFAESCipher {
        public AES_ECB_PKCS5Padding() {
            super(SDFMode.ECB, SDFPadding.PKCS5PADDING, -1);
        }
    }
    public static final class AES_CBC_NoPadding extends SDFAESCipher {
        public AES_CBC_NoPadding() {
            super(SDFMode.CBC, SDFPadding.NOPADDING, -1);
        }
    }
    public static final class AES_CBC_PKCS5Padding extends SDFAESCipher {
        public AES_CBC_PKCS5Padding() {
            super(SDFMode.CBC, SDFPadding.PKCS5PADDING, -1);
        }
    }
    public static final class AES_XTS_NoPadding extends SDFAESCipher {
        public AES_XTS_NoPadding() {
            super(SDFMode.XTS, SDFPadding.NOPADDING, -1);
        }
    }
    public static final class AES_GCM_NoPadding extends SDFAESCipher {
        public AES_GCM_NoPadding() {
            super(SDFMode.GCM, SDFPadding.NOPADDING, -1);
        }
    }

    public static final class AES128_ECB_NoPadding extends SDFAESCipher {
        public AES128_ECB_NoPadding() {
            super(SDFMode.ECB, SDFPadding.NOPADDING, 16);
        }
    }
    public static final class AES128_ECB_PKCS5Padding extends SDFAESCipher {
        public AES128_ECB_PKCS5Padding() {
            super(SDFMode.ECB, SDFPadding.PKCS5PADDING, 16);
        }
    }
    public static final class AES128_CBC_NoPadding extends SDFAESCipher {
        public AES128_CBC_NoPadding() {
            super(SDFMode.CBC, SDFPadding.NOPADDING, 16);
        }
    }
    public static final class AES128_CBC_PKCS5Padding extends SDFAESCipher {
        public AES128_CBC_PKCS5Padding() {
            super(SDFMode.CBC, SDFPadding.PKCS5PADDING, 16);
        }
    }
    public static final class AES128_XTS_NoPadding extends SDFAESCipher {
        public AES128_XTS_NoPadding() {
            super(SDFMode.XTS, SDFPadding.NOPADDING, 16);
        }
    }
    public static final class AES128_GCM_NoPadding extends SDFAESCipher {
        public AES128_GCM_NoPadding() {
            super(SDFMode.GCM, SDFPadding.NOPADDING, 16);
        }
    }

    public static final class AES192_ECB_NoPadding extends SDFAESCipher {
        public AES192_ECB_NoPadding() {
            super(SDFMode.ECB, SDFPadding.NOPADDING, 24);
        }
    }
    public static final class AES192_ECB_PKCS5Padding extends SDFAESCipher {
        public AES192_ECB_PKCS5Padding() {
            super(SDFMode.ECB, SDFPadding.PKCS5PADDING, 24);
        }
    }
    public static final class AES192_CBC_NoPadding extends SDFAESCipher {
        public AES192_CBC_NoPadding() {
            super(SDFMode.CBC, SDFPadding.NOPADDING, 24);
        }
    }
    public static final class AES192_CBC_PKCS5Padding extends SDFAESCipher {
        public AES192_CBC_PKCS5Padding() {
            super(SDFMode.CBC, SDFPadding.PKCS5PADDING, 24);
        }
    }
    public static final class AES192_XTS_NoPadding extends SDFAESCipher {
        public AES192_XTS_NoPadding() {
            super(SDFMode.XTS, SDFPadding.NOPADDING, 24);
        }
    }
    public static final class AES192_GCM_NoPadding extends SDFAESCipher {
        public AES192_GCM_NoPadding() {
            super(SDFMode.GCM, SDFPadding.NOPADDING, 24);
        }
    }

    public static final class AES256_ECB_NoPadding extends SDFAESCipher {
        public AES256_ECB_NoPadding() {
            super(SDFMode.ECB, SDFPadding.NOPADDING, 32);
        }
    }
    public static final class AES256_ECB_PKCS5Padding extends SDFAESCipher {
        public AES256_ECB_PKCS5Padding() {
            super(SDFMode.ECB, SDFPadding.PKCS5PADDING, 32);
        }
    }
    public static final class AES256_CBC_NoPadding extends SDFAESCipher {
        public AES256_CBC_NoPadding() {
            super(SDFMode.CBC, SDFPadding.NOPADDING, 32);
        }
    }
    public static final class AES256_CBC_PKCS5Padding extends SDFAESCipher {
        public AES256_CBC_PKCS5Padding() {
            super(SDFMode.CBC, SDFPadding.PKCS5PADDING, 32);
        }
    }
    public static final class AES256_XTS_NoPadding extends SDFAESCipher {
        public AES256_XTS_NoPadding() {
            super(SDFMode.XTS, SDFPadding.NOPADDING, 32);
        }
    }
    public static final class AES256_GCM_NoPadding extends SDFAESCipher {
        public AES256_GCM_NoPadding() {
            super(SDFMode.GCM, SDFPadding.NOPADDING, 32);
        }
    }

    SDFAESCipher(SDFMode mode, SDFPadding padding, int supportedKeySize) {
        super(SDFDataKeyType.DATA_KEY_AES, mode, padding, 16, supportedKeySize);
    }

    @Override
    protected void checkPlainKeySize(int keySize) throws InvalidKeyException {
        if (supportedKeySize != -1) {
            super.checkPlainKeySize(keySize);
            return;
        }

        if (SDFKeyUtil.isAESKeySizeValid(keySize)) {
            throw new InvalidKeyException("Invalid AES plain key length :" + keySize + "bytes");
        }
    }
}

