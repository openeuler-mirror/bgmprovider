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
     * Extended error code
     */
    SWR_INVALID_USER(0x01010001L),
    SWR_INVALID_AUTHENCODE(0x01010002L),
    SWR_PROTOCOL_VER_ERR(0x01010003L),
    SWR_INVALID_COMMAND(0x01010004L),
    SWR_INVALID_PARAMETERS(0x01010005L),
    SWR_FILE_ALREADY_EXIST(0x01010006L),
    SWR_SYNCH_ERR(0x01010007L),
    SWR_SYNCH_LOGIN_ERR(0x01010008L),

    SWR_SOCKET_TIMEOUT(0x01010100L),
    SWR_CONNECT_ERR(0x01010101L),
    SWR_SET_SOCKOPT_ERR(0x01010102L),
    SWR_SOCKET_SEND_ERR(0x01010104L),
    SWR_SOCKET_RECV_ERR(0x01010105L),
    SWR_SOCKET_RECV_0(0x01010106L),

    SWR_SEM_TIMEOUT(0x01010200L),
    SWR_NO_AVAILABLE_HSM(0x01010201L),
    SWR_NO_AVAILABLE_CSM(0x01010202L),
    SWR_CONFIG_ERR(0x01010301L),

    /**
     * Encryption card error code
     */
    SWR_CARD_UNKNOWERR(0x01020001L),
    SWR_CARD_NOTSUPPORT(0x01020002L),
    SWR_CARD_COMMFAIL(0x01020003L),
    SWR_CARD_HARDFAIL(0x01020004L),
    SWR_CARD_OPENDEVICE(0x01020005L),
    SWR_CARD_OPENSESSION(0x01020006L),
    SWR_CARD_PARDENY(0x01020007L),
    SWR_CARD_KEYNOTEXIST(0x01020008L),
    SWR_CARD_ALGNOTSUPPORT(0x01020009L),
    SWR_CARD_ALGMODNOTSUPPORT(0x01020010L),
    SWR_CARD_PKOPERR(0x01020011L),
    SWR_CARD_SKOPERR(0x01020012L),
    SWR_CARD_SIGNERR(0x01020013L),
    SWR_CARD_VERIFYERR(0x01020014L),
    SWR_CARD_SYMOPERR(0x01020015L),
    SWR_CARD_STEPERR(0x01020016L),
    SWR_CARD_FILESIZEERR(0x01020017L),
    SWR_CARD_FILENOEXIST(0x01020018L),
    SWR_CARD_FILEOFSERR(0x01020019L),
    SWR_CARD_KEYTYPEERR(0x01020020L),
    SWR_CARD_KEYERR(0x01020021L),
    SWR_CARD_BUFFER_TOO_SMALL(0x01020101L),
    SWR_CARD_DATA_PAD(0x01020102L),
    SWR_CARD_DATA_SIZE(0x01020103L),
    SWR_CARD_CRYPTO_NOT_INIT(0x01020104L),

    /**
     * 01/03/09 version of encryption card permission management error code
     */
    SWR_CARD_MANAGEMENT_DENY(0x01021001L),
    SWR_CARD_OPERATION_DENY(0x01021002L),
    SWR_CARD_DEVICE_STATUS_ERR(0x01021003L),
    SWR_CARD_LOGIN_ERR(0x01021011L),
    SWR_CARD_USERID_ERR(0x01021012L),
    SWR_CARD_PARAMENT_ERR(0x01021013L),


    /**
     * 05/06 version of encryption card permission management error code
     */
    SWR_CARD_MANAGEMENT_DENY_05(0x01020801L),
    SWR_CARD_OPERATION_DENY_05(0x01020802L),
    SWR_CARD_DEVICE_STATUS_ERR_05(0x01020803L),
    SWR_CARD_LOGIN_ERR_05(0x01020811L),
    SWR_CARD_USERID_ERR_05(0x01020812L),
    SWR_CARD_PARAMENT_ERR_05(0x01020813L),

    /**
     * Card reader error code
     */
    SWR_CARD_READER_PIN_ERROR(0x010363CEL),
    SWR_CARD_READER_NO_CARD(0x0103FF01L),
    SWR_CARD_READER_CARD_INSERT(0x0103FF02L),
    SWR_CARD_READER_CARD_INSERT_TYPE(0x0103FF03L),

    /**
     * Custom extended error code
     */
    EPRI_PLAINK0INDEX(0x01050001L),
    EPRI_K0NOTEXIST(0x01050002L),
    EPRI_KEYLENERR(0x01050003L),
    EPRI_KEYINDEXERR(0x01050004L),
    EPRI_KEYPADDINGERR(0x01050005L),
    EPRI_NOTEXPORT(0x01050006L),
    EPRI_MUSTDECENT(0x01050007L),
    EPRI_NOTENCRPTKEY(0x01050008L),
    EPRI_NOTDECRPTKEY(0x01050009L),
    EPRI_MACVERIFYERR(0x0105000AL),
    EPRI_PUBKEYSTORAGEERR(0x0105000BL),
    EPRI_KEYEXIST(0x0105000CL),
    EPRI_MALLOCERR(0x0105000DL);

    private final long code;

    SDFErrorCode(long code) {
        this.code = code;
    }

    public long getCode() {
        return code;
    }

}
