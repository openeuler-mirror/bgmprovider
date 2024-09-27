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

package org.openeuler.sdf.commons.exception;

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.sdf.commons.exception.SDFErrorCode;
import org.openeuler.sdf.commons.exception.SDFException;
import sun.security.pkcs11.wrapper.Functions;

public class SDFExceptionTest {

    @Test
    public void testValidErrorCode() {
        SDFErrorCode[] sdfErrorCodes = SDFErrorCode.values();
        for (SDFErrorCode sdfErrorCode : sdfErrorCodes) {
            SDFException exception = new SDFException(sdfErrorCode.getCode());
            String expectedMessage = getValidMessage(sdfErrorCode);
            Assert.assertEquals(expectedMessage, exception.getMessage());
        }
    }

    @Test
    public void testInvalidErrorCode() {
        long[] invalidErrorCodes = new long[]{0x01000016L, 0x01010009L, 0x01020105L, 0x01030001L, 0x80000000L};
        for (long invalidErrorCode : invalidErrorCodes) {
            SDFException exception = new SDFException(invalidErrorCode);
            String expectedMessage = getInvalidMessage(invalidErrorCode);
            Assert.assertEquals(expectedMessage, exception.getMessage());
        }
    }

    private static String getInvalidMessage(long errorCode) {
        return String.format("0x%s(%s)", getCodeStr(errorCode), "UNKNOWN_ERROR");
    }

    private static String getValidMessage(SDFErrorCode sdfErrorCode) {
        return String.format("0x%s(%s)", getCodeStr(sdfErrorCode.getCode()), sdfErrorCode.name());
    }

    private static String getCodeStr(long errorCode) {
        String codeStr;
        if ((errorCode & 0x80000000L) != 0) {
            codeStr = Functions.toFullHexString(errorCode);
        } else {
            codeStr = Functions.toFullHexString((int) errorCode);
        }
        return codeStr;
    }
}
