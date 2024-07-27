/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.sun.security.ssl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.*;
import javax.net.ssl.SSLHandshakeException;

import org.openeuler.spec.ECCPremasterSecretKeySpec;
import org.openeuler.sun.security.internal.spec.TlsECCKeyAgreementParameterSpec;

final class ECCKeyExchange {
    static final SSLPossessionGenerator poGenerator =
            new ECCPossessionGenerator();
    static final SSLKeyAgreementGenerator kaGenerator =
            new ECCKAGenerator();

    private static final class ECCPossessionGenerator
            implements SSLPossessionGenerator {
        // Prevent instantiation of this class.
        private ECCPossessionGenerator() {
            // blank
        }

        @Override
        public SSLPossession createPossession(HandshakeContext context) {
            return null;
        }
    }

    static final
            class ECCPremasterSecret implements SSLPossession, SSLCredentials {
        final ECCPremasterSecretKeySpec premasterSecret;

        ECCPremasterSecret(ECCPremasterSecretKeySpec premasterSecret) {
            this.premasterSecret = premasterSecret;
        }

        byte[] getEncoded(PublicKey publicKey,
                SecureRandom secureRandom) throws GeneralSecurityException {
            return premasterSecret.getEncryptedKey();
        }

        @SuppressWarnings("deprecation")
        static ECCPremasterSecret createPremasterSecret(
                PublicKey publicKey,
                ClientHandshakeContext chc) throws GeneralSecurityException {
            String algorithm = "GmTlsEccPremasterSecret";
            KeyAgreement keyAgreement = JsseJce.getKeyAgreement(algorithm);

            TlsECCKeyAgreementParameterSpec spec =
                    new TlsECCKeyAgreementParameterSpec(
                            chc.clientHelloVersion,
                            chc.negotiatedProtocol.id);
            keyAgreement.init(publicKey, spec, chc.sslContext.getSecureRandom());
            ECCPremasterSecretKeySpec preMaster = (ECCPremasterSecretKeySpec) keyAgreement.generateSecret("TlsEccPremasterSecret");

            return new ECCPremasterSecret(preMaster);
        }

        @SuppressWarnings("deprecation")
        static ECCPremasterSecret decode(ServerHandshakeContext shc,
                PrivateKey privateKey,
                byte[] encrypted) throws GeneralSecurityException {
            String algorithm = "GmTlsEccPremasterSecret";
            KeyAgreement keyAgreement = JsseJce.getKeyAgreement(algorithm);

            TlsECCKeyAgreementParameterSpec spec =
                    new TlsECCKeyAgreementParameterSpec(
                            encrypted,
                            shc.clientHelloVersion,
                            shc.negotiatedProtocol.id,
                            false);
            keyAgreement.init(privateKey, spec);
            ECCPremasterSecretKeySpec preMaster = (ECCPremasterSecretKeySpec) keyAgreement.generateSecret("TlsEccPremasterSecret");

            return new ECCPremasterSecret(preMaster);
        }
    }

    private static final
            class ECCKAGenerator implements SSLKeyAgreementGenerator {
        // Prevent instantiation of this class.
        private ECCKAGenerator() {
            // blank
        }

        @Override
        public SSLKeyDerivation createKeyDerivation(
                HandshakeContext context) throws IOException {
            ECCPremasterSecret premaster = null;
            if (context instanceof ClientHandshakeContext) {
                for (SSLPossession possession : context.handshakePossessions) {
                    if (possession instanceof ECCPremasterSecret) {
                        premaster = (ECCPremasterSecret)possession;
                        break;
                    }
                }
            } else {
                for (SSLCredentials credential : context.handshakeCredentials) {
                    if (credential instanceof ECCPremasterSecret) {
                        premaster = (ECCPremasterSecret)credential;
                        break;
                    }
                }
            }

            if (premaster == null) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "No sufficient ECC key agreement parameters negotiated");
            }

            return new ECCKAKeyDerivation(context, premaster.premasterSecret);
        }

        private static final
                class ECCKAKeyDerivation implements SSLKeyDerivation {
            private final HandshakeContext context;
            private final SecretKey preMasterSecret;

            ECCKAKeyDerivation(
                    HandshakeContext context, SecretKey preMasterSecret) {
                this.context = context;
                this.preMasterSecret = preMasterSecret;
            }

            @Override
            public SecretKey deriveKey(String algorithm,
                    AlgorithmParameterSpec params) throws IOException {
                SSLMasterKeyDerivation mskd =
                        SSLMasterKeyDerivation.valueOf(
                                context.negotiatedProtocol);
                if (mskd == null) {
                    // unlikely
                    throw new SSLHandshakeException(
                            "No expected master key derivation for protocol: " +
                            context.negotiatedProtocol.name);
                }
                SSLKeyDerivation kd = mskd.createKeyDerivation(
                        context, preMasterSecret);
                return kd.deriveKey("MasterSecret", params);
            }
        }
    }
}
