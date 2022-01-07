/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.tomcat;

import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;

public enum Cert {
    KEYSTORE_SM2(Type.EC, "server-sm2-sig,server-sm2-enc",
            "12345678",
            TestUtils.getPaths(new String[]{
                    "keystore/server-sm2-sig.keystore", "keystore/server-sm2-enc.keystore"
            }),
            "PKCS12"),
    KEYSTORE_SM2_EC(Type.EC, "server-sm2-sig,server-sm2-enc,server-ec",
            "12345678",
            TestUtils.getPaths(new String[]{
                    "keystore/server-sm2-sig.keystore", "keystore/server-sm2-enc.keystore", "keystore/server-ec.keystore"
            }),
            "PKCS12"),
    KEYSTORE_SM2_RSA(Type.UNDEFINED, "server-sm2-sig,server-sm2-enc,server-rsa",
            "12345678",
            TestUtils.getPaths(new String[]{
                    "keystore/server-sm2-sig.keystore", "keystore/server-sm2-enc.keystore", "keystore/server-rsa.keystore"
            }),
            "PKCS12"),

    PEM_SM2(Type.UNDEFINED, "server-sm2-sig,server-sm2-enc",
            "12345678",
            TestUtils.getPaths(new String[]{
                    "pem/server-sm2-sig-key.pem", "pem/server-sm2-enc-key.pem"
            }),
            TestUtils.getPaths(new String[]{
                    "pem/server-sm2-sig-cert.pem", "pem/server-sm2-enc-cert.pem"
            }),
            null
    ),
    PEM_SM2_EC(Type.EC, "server-sm2-sig,server-sm2-enc,server-ec",
            "12345678",
            TestUtils.getPaths(new String[]{
                    "pem/server-sm2-sig-key.pem", "pem/server-sm2-enc-key.pem", "pem/server-ec-key.pem"
            }),
            TestUtils.getPaths(new String[]{
                    "pem/server-sm2-sig-cert.pem", "pem/server-sm2-enc-cert.pem", "pem/server-ec-cert.pem"
            }),
            null
    ),
    PEM_SM2_RSA(Type.UNDEFINED, "server-sm2-sig,server-sm2-enc,server-rsa",
            "12345678",
            TestUtils.getPaths(new String[]{
                    "pem/server-sm2-sig-key.pem", "pem/server-sm2-enc-key.pem", "pem/server-rsa-key.pem"
            }),
            TestUtils.getPaths(new String[]{
                    "pem/server-sm2-sig-cert.pem", "pem/server-sm2-enc-cert.pem", "pem/server-rsa-cert.pem"
            }),
            null
    );

    private final FileType fileType;
    private final Type certType;
    private final String keyAlias;
    private final String password;
    private String keyStoreFile;
    private String keyStoreType;
    private String keyFile;
    private String certFile;
    private String chainFile;

    Cert(FileType fileType, Type certType, String keyAlias, String password) {
        this.fileType = fileType;
        this.certType = certType;
        this.keyAlias = keyAlias;
        this.password = password;
    }

    // KEYSTORE
    Cert(Type certType, String keyAlias, String password,
         String keyStoreFile, String keyStoreType) {
        this(FileType.KEYSTORE, certType, keyAlias, password);
        this.keyStoreFile = keyStoreFile;
        this.keyStoreType = keyStoreType;
    }

    // PEM
    Cert(Type certType, String keyAlias, String password,
         String keyFile, String certFile, String chainFile) {
        this(FileType.PEM, certType, keyAlias, password);
        this.keyFile = keyFile;
        this.certFile = certFile;
        this.chainFile = chainFile;
    }

    public FileType getFileType() {
        return fileType;
    }

    public Type getCertType() {
        return certType;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public String getPassword() {
        return password;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public String getCertFile() {
        return certFile;
    }

    public String getChainFile() {
        return chainFile;
    }

    public enum FileType {
        KEYSTORE, PEM
    }
}