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

/**
 * SDF error code definition
 */
public enum SDFErrorCode {

    /**
     * Standard error code
     */
    SDR_OK(0x00000000L),
    SDR_UNKNOWERR(0x01000001L),
    SDR_NOTSUPPORT(0x01000002L),
    SDR_COMMFAIL(0x01000003L),
    SDR_HARDFAIL(0x01000004L),
    SDR_OPENDEVICE(0x01000005L),
    SDR_OPENSESSION(0x01000006L),
    SDR_PARDENY(0x01000007L),
    SDR_KEYNOTEXIST(0x01000008L),
    SDR_ALGNOTSUPPORT(0x01000009L),
    SDR_ALGMODNOTSUPPORT(0x0100000AL),
    SDR_PKOPERR(0x0100000BL),
    SDR_SKOPERR(0x0100000CL),
    SDR_SIGNERR(0x0100000DL),
    SDR_VERIFYERR(0x0100000EL),
    SDR_SYMOPERR(0x0100000FL),
    SDR_STEPERR(0x01000010L),
    SDR_FILESIZEERR(0x01000011L),
    SDR_FILENOEXIST(0x01000012L),
    SDR_FILEOFSERR(0x01000013L),
    SDR_KEYTYPEERR(0x01000014L),
    SDR_KEYERR(0x01000015L),

    /**
     * Additional error code definitions
     */
    SDR_ARGUMENTERR(0x01000016L),
    SDR_MEMALLOCERR(0x01000017L),
    SDR_MEMCPYERR(0x01000018L),
    SDR_MEMNOTENOUGH(0x01000019L),
    SDR_FILEACCESSERR(0x01000020L),
    SDR_CONFIGINITERR(0x01000021L),
    SDR_CARDINITERR(0x01000023L),

    /**
     * Additional error code definitions - log module
     */
    SDR_LOG_ERR(0x01100000L),
    SDR_LOGINITERR(0x01100001L),
    SDR_LOGLEVELERR(0x01100002L),
    SDR_LOGPATHERR(0x01100003L),
    SDR_LOGFILESIZEERR(0x01100004L),
    SDR_LOGROTATEERR(0x01100005L),


    /**
     * Protocol error code
     */
    PROTOCOL_BASE(0x02000000L),
    PROTOCOL_CMDERR(0x02000001L),


    /**
     * KEK error code
     */
    KEK_BASE(0x03000000L),
    KEK_NO_UPDATE_AUTH(0x03000001L),
    KEK_NEED_PULL(0x03000002L);

    private final long code;

    SDFErrorCode(long code) {
        this.code = code;
    }

    public long getCode() {
        return code;
    }

}
