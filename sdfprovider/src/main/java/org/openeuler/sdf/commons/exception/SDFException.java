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

import sun.security.pkcs11.wrapper.Functions;

import java.util.HashMap;
import java.util.Map;

/**
 * This is the class that handles encryption card exceptions
 */
public class SDFException extends Exception {
    private static final long serialVersionUID = -5328824333039362164L;
    protected long errorCode;
    protected String functionName;

    protected String errorMsg;

    private static final Map<Long, SDFErrorCode> errorCodeMap = new HashMap<>();

    static {
        initSDFErrorCode();
    }

    private static void initSDFErrorCode() {
        SDFErrorCode[] errorCodes = SDFErrorCode.values();
        for (SDFErrorCode errorCode : errorCodes) {
            errorCodeMap.put(errorCode.getCode(), errorCode);
        }
    }

    public SDFException(long errorCode) {
        this.errorCode = errorCode;
        this.errorMsg = lookup(errorCode);
    }

    public SDFException(long errorCode, String functionName) {
        this.errorCode = errorCode;
        this.functionName = functionName;
        this.errorMsg = functionName + ":" + lookup(errorCode);
    }

    @Override
    public String getMessage() {
        return this.errorMsg;
    }

    public long getErrorCode() {
        return this.errorCode;
    }

    private static String lookup(long errorCode) {
        String codeStr;
        if ((errorCode & 0x80000000L) != 0) {
            codeStr = Functions.toFullHexString(errorCode);
        } else {
            codeStr = Functions.toFullHexString((int) errorCode);
        }
        SDFErrorCode sdfErrorCode = errorCodeMap.get(errorCode);
        return String.format("0x%s(%s)", codeStr, sdfErrorCode != null ? sdfErrorCode.name() : "UNKNOWN_ERROR");
    }
}
