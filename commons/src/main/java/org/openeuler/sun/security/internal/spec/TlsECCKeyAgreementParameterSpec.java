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

package org.openeuler.sun.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Parameters for GMTLS ECC premaster secret.
 *
 * Reference TlsRSAKeyAgreementParameterSpec
 *
 * <p>Instances of this class are immutable.
 */
@Deprecated
public class TlsECCKeyAgreementParameterSpec
        implements AlgorithmParameterSpec {

    // Client Premaster Secret Encrypted by Public Key
    private final byte[] encryptedSecret;

    private final static String PROP_NAME =
                                "com.sun.net.ssl.eccPreMasterSecretFix";

    private final static boolean eccPreMasterSecretFix =
            AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
                public Boolean run() {
                    String value = System.getProperty(PROP_NAME);
                    if (value != null && value.equalsIgnoreCase("true")) {
                        return Boolean.TRUE;
                    }

                    return Boolean.FALSE;
                }
            });

    private final int clientVersion;
    private final int serverVersion;

    private final boolean isClient;

    /**
     * Constructs a new TlsRsaPremasterSecretParameterSpec.
     *
     * @param clientVersion the version of the TLS protocol by which the
     *        client wishes to communicate during this session
     * @param serverVersion the negotiated version of the TLS protocol which
     *        contains the lower of that suggested by the client in the client
     *        hello and the highest supported by the server.
     *
     * @throws IllegalArgumentException if clientVersion or serverVersion are
     *   negative or larger than (2^16 - 1)
     */
    public TlsECCKeyAgreementParameterSpec(
            int clientVersion, int serverVersion) {

        this.clientVersion = checkVersion(clientVersion);
        this.serverVersion = checkVersion(serverVersion);
        this.encryptedSecret = null;
        this.isClient = true;
    }

    /**
     * Constructs a new TlsRsaPremasterSecretParameterSpec.
     *
     * @param clientVersion the version of the TLS protocol by which the
     *        client wishes to communicate during this session
     * @param serverVersion the negotiated version of the TLS protocol which
     *        contains the lower of that suggested by the client in the client
     *        hello and the highest supported by the server.
     * @param encodedSecret the encoded secret key
     *
     * @throws IllegalArgumentException if clientVersion or serverVersion are
     *   negative or larger than (2^16 - 1) or if encodedSecret is not
     *   exactly 48 bytes
     */
    public TlsECCKeyAgreementParameterSpec(
            int clientVersion, int serverVersion, byte[] encryptedSecret) {

        this.clientVersion = checkVersion(clientVersion);
        this.serverVersion = checkVersion(serverVersion);
        if (encryptedSecret == null) {
            throw new IllegalArgumentException(
                        "Encrypted secret cannot be null");
        }
        this.encryptedSecret = encryptedSecret.clone();
        this.isClient = true;
    }

    public TlsECCKeyAgreementParameterSpec(byte[] encryptedSecret, int clientVersion, int serverVersion, boolean isClient) {
        this.clientVersion = checkVersion(clientVersion);
        this.serverVersion = checkVersion(serverVersion);
        if (encryptedSecret == null) {
            throw new IllegalArgumentException(
                    "Encrypted secret cannot be null");
        }
        this.encryptedSecret = encryptedSecret.clone();
        this.isClient = isClient;
    }

    /**
     * Returns the version of the TLS protocol by which the client wishes to
     * communicate during this session.
     *
     * @return the version of the TLS protocol in ClientHello message
     */
    public int getClientVersion() {
        return clientVersion;
    }

    /**
     * Returns the negotiated version of the TLS protocol which contains the
     * lower of that suggested by the client in the client hello and the
     * highest supported by the server.
     *
     * @return the negotiated version of the TLS protocol in ServerHello message
     */
    public int getServerVersion() {
        return serverVersion;
    }

    /**
     * Returns the major version used in ECC premaster secret.
     *
     * @return the major version used in ECC premaster secret.
     */
    public int getMajorVersion() {
        if (eccPreMasterSecretFix || clientVersion >= 0x0302) {
                                                        // 0x0302: TLSv1.1
            return (clientVersion >>> 8) & 0xFF;
        }

        return (serverVersion >>> 8) & 0xFF;
    }

    /**
     * Returns the minor version used in ECC premaster secret.
     *
     * @return the minor version used in ECC premaster secret.
     */
    public int getMinorVersion() {
        if (eccPreMasterSecretFix || clientVersion >= 0x0302) {
                                                        // 0x0302: TLSv1.1
            return clientVersion & 0xFF;
        }

        return serverVersion & 0xFF;
    }

    private int checkVersion(int version) {
        if ((version < 0) || (version > 0xFFFF)) {
            throw new IllegalArgumentException(
                        "Version must be between 0 and 65,535");
        }
        return version;
    }

    /**
     * Returns the encrypted secret.
     *
     * @return the encrypted secret, may be null if no encrypted secret.
     */
    public byte[] getEncryptedSecret() {
        return encryptedSecret == null ? null : encryptedSecret.clone();
    }

    public boolean isClient() {
        return isClient;
    }
}
