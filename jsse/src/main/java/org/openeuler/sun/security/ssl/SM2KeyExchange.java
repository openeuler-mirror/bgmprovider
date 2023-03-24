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
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;

import org.openeuler.SM2KeyExchangeUtil;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.NamedGroup;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.NamedGroupType;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.SupportedGroups;
import org.openeuler.sun.security.ssl.GMX509Authentication.GMX509Possession;
import sun.security.util.ECUtil;

final class SM2KeyExchange {
    static final SSLPossessionGenerator poGenerator =
            new SM2PossessionGenerator();
    static final SSLKeyAgreementGenerator sm2KAGenerator =
            new SM2KAGenerator();

    static final class SM2Credentials implements SSLCredentials {
        final ECPublicKey popPublicKey;
        final NamedGroup namedGroup;
        final byte[] peerEncodePoint;

        SM2Credentials(ECPublicKey popPublicKey, NamedGroup namedGroup, byte[] encodePoint) {
            this.popPublicKey = popPublicKey;
            this.namedGroup = namedGroup;
            this.peerEncodePoint = encodePoint;
        }
    }

    static final class SM2Possession implements SSLPossession {
        final PrivateKey privateKey;
//        final BCECPublicKey publicKey;
        final ECPublicKey publicKey;
        final NamedGroup namedGroup;
        final BigInteger randomNum;

        SM2Possession(NamedGroup namedGroup, SecureRandom random, ConnectionContext context) {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;

            GMX509Possession gmx509Possession = null;
            if (shc.interimAuthn instanceof GMX509Possession) {
                gmx509Possession = ((GMX509Possession)shc.interimAuthn);
            }

            if (gmx509Possession != null) {
//                publicKey = (BCECPublicKey) gmx509Possession.popEncCerts[0].
//                        getPublicKey();
//                privateKey = gmx509Possession.popEncPrivateKey;
//                randomNum = SM2KeyExchangeUtil.generateRandom(
//                        publicKey.getParameters().getN(), random);

                publicKey = (ECPublicKey) gmx509Possession.popEncCerts[0].
                        getPublicKey();
                privateKey = gmx509Possession.popEncPrivateKey;
                randomNum = SM2KeyExchangeUtil.generateRandom(
                         publicKey.getParams().getOrder(), random);
            } else {
                publicKey = null;
                privateKey = null;
                randomNum = null;
            }

            this.namedGroup = namedGroup;
        }

        SM2Possession(SM2Credentials credentials, SecureRandom random, ConnectionContext context) {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;

            GMX509Possession gmx509Possession = null;
            for (SSLPossession possession : chc.handshakePossessions) {
                if (possession instanceof GMX509Possession) {
                    gmx509Possession = (GMX509Possession)possession;
                    break;
                }
            }

            if (gmx509Possession != null) {
//                publicKey = (BCECPublicKey) gmx509Possession.popEncCerts[0].
//                        getPublicKey();
//                privateKey = gmx509Possession.popEncPrivateKey;
//                randomNum = SM2KeyExchangeUtil.generateRandom(
//                        publicKey.getParameters().getN(), random);

                publicKey = (ECPublicKey) gmx509Possession.popEncCerts[0].
                        getPublicKey();
                privateKey = gmx509Possession.popEncPrivateKey;
                randomNum = SM2KeyExchangeUtil.generateRandom(
                        publicKey.getParams().getOrder(), random);
            } else {
                publicKey = null;
                privateKey = null;
                randomNum = null;
            }

            this.namedGroup = credentials.namedGroup;
        }

        @Override
        public byte[] encode() {
//            return ECUtil.encodePoint(
//                    publicKey.getW(), publicKey.getParams().getCurve());
            return ECUtil.encodePoint(
                    publicKey.getW(), publicKey.getParams().getCurve());
        }
    }

    private static final
            class SM2PossessionGenerator implements SSLPossessionGenerator {
        // Prevent instantiation of this class.
        private SM2PossessionGenerator() {
            // blank
        }

        @Override
        public SSLPossession createPossession(HandshakeContext context) {
            NamedGroup preferableNamedGroup = null;
            ProtocolVersion protocolVersion = context.t12WithGMCipherSuite ?
                    ProtocolVersion.GMTLS : context.negotiatedProtocol;
            if ((context.clientRequestedNamedGroups != null) &&
                    (!context.clientRequestedNamedGroups.isEmpty())) {
                preferableNamedGroup = SupportedGroups.getPreferredGroup(
                        protocolVersion,
                        context.algorithmConstraints,
                        NamedGroupType.NAMED_GROUP_ECDHE,
                        context.clientRequestedNamedGroups);
            } else {
                preferableNamedGroup = SupportedGroups.getPreferredGroup(
                        protocolVersion,
                        context.algorithmConstraints,
                        NamedGroupType.NAMED_GROUP_ECDHE);
            }

            if (preferableNamedGroup != null) {
                return new SM2Possession(preferableNamedGroup,
                            context.sslContext.getSecureRandom(), context);
            }

            // no match found, cannot use this cipher suite.
            //
            return null;
        }
    }

    private static final
            class SM2KAGenerator implements SSLKeyAgreementGenerator {
        // Prevent instantiation of this class.
        private SM2KAGenerator() {
            // blank
        }

        @Override
        public SSLKeyDerivation createKeyDerivation(
                HandshakeContext context) throws IOException {
            SM2Possession sm2Possession = null;
            SM2Credentials sm2Credentials = null;
            for (SSLPossession poss : context.handshakePossessions) {
                if (!(poss instanceof SM2Possession)) {
                    continue;
                }

                NamedGroup ng = ((SM2Possession)poss).namedGroup;
                for (SSLCredentials cred : context.handshakeCredentials) {
                    if (!(cred instanceof SM2Credentials)) {
                        continue;
                    }
                    if (ng.equals(((SM2Credentials)cred).namedGroup)) {
                        sm2Credentials = (SM2Credentials)cred;
                        break;
                    }
                }

                if (sm2Credentials != null) {
                    sm2Possession = (SM2Possession)poss;
                    break;
                }
            }

            if (sm2Possession == null || sm2Credentials == null) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "No sufficient sm2 key agreement parameters negotiated");
            }

            return new SM2KAKeyDerivation(context,
                sm2Possession.privateKey, sm2Credentials.popPublicKey);
        }
    }

    private static final
            class SM2KAKeyDerivation implements SSLKeyDerivation {
        private final HandshakeContext context;
        private final PrivateKey localPrivateKey;
        private final PublicKey peerPublicKey;

        SM2KAKeyDerivation(HandshakeContext context,
                PrivateKey localPrivateKey,
                PublicKey peerPublicKey) {
            this.context = context;
            this.localPrivateKey = localPrivateKey;
            this.peerPublicKey = peerPublicKey;
        }

        @Override
        public SecretKey deriveKey(String algorithm,
                AlgorithmParameterSpec params) throws IOException {
            return gmtlsDeriveKey(algorithm, params);
        }

        private SecretKey gmtlsDeriveKey(String algorithm,
                                       AlgorithmParameterSpec params) throws IOException {
            try {
                KeyAgreement ka = JsseJce.getKeyAgreement("SM2");
                ka.init(localPrivateKey, params, null);
                ka.doPhase(peerPublicKey, true);
                SecretKey preMasterSecret =
                        ka.generateSecret("TlsPremasterSecret");

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
            } catch (GeneralSecurityException gse) {
                throw (SSLHandshakeException) new SSLHandshakeException(
                    "Could not generate secret").initCause(gse);
            }
        }

    }
}
