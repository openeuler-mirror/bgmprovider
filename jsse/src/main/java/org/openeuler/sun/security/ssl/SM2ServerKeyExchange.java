/*
 * Copyright (c) 2015, 2018, Oracle and/or its affiliates. All rights reserved.
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
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Map;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.openeuler.SM2KeyExchangeUtil;
import org.openeuler.sun.security.ssl.SM2KeyExchange.SM2Credentials;
import org.openeuler.sun.security.ssl.SM2KeyExchange.SM2Possession;
import org.openeuler.sun.security.ssl.SSLHandshake.HandshakeMessage;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.NamedGroup;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.SupportedGroups;
import org.openeuler.sun.security.ssl.GMX509Authentication.GMX509Credentials;
import org.openeuler.sun.security.ssl.GMX509Authentication.GMX509Possession;
import org.openeuler.sun.misc.HexDumpEncoder;

/**
 * Pack of the ServerKeyExchange handshake message.
 */
final class SM2ServerKeyExchange {
    static final SSLConsumer sm2HandshakeConsumer =
            new SM2ServerKeyExchangeConsumer();
    static final HandshakeProducer sm2HandshakeProducer =
            new SM2ServerKeyExchangeProducer();

    /**
     * The SM2 ServerKeyExchange handshake message.
     */
    private static final
            class SM2ServerKeyExchangeMessage extends HandshakeMessage {
        private static final byte CURVE_NAMED_CURVE = (byte)0x03;

        // id of the named curve
        private final NamedGroup namedGroup;

        // encoded public point
        private final byte[] publicPoint;

        // signature bytes, or null if anonymous
        private final byte[] paramsSignature;

        private final boolean useExplicitSigAlgorithm;

        // the signature algorithm used by this ServerKeyExchange message
        private final SignatureScheme signatureScheme;

        private final int curveId;

        SM2ServerKeyExchangeMessage(
                HandshakeContext handshakeContext) throws IOException {
            super(handshakeContext);
            this.curveId = 23;

            // This happens in server side only.
            ServerHandshakeContext shc =
                    (ServerHandshakeContext)handshakeContext;

            SM2Possession sm2Possession = null;
            GMX509Possession gmx509Possession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof SM2Possession) {
                    sm2Possession = (SM2Possession)possession;
                    if (gmx509Possession != null) {
                        break;
                    }
                } else if (possession instanceof GMX509Possession) {
                    gmx509Possession = (GMX509Possession)possession;
                    if (sm2Possession != null) {
                        break;
                    }
                }
            }

            if (sm2Possession == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "No SM2 credentials negotiated for server key exchange");
            }

            BCECPublicKey publicKey = sm2Possession.publicKey;
            ECParameterSpec params = publicKey.getParams();
            publicPoint = SM2KeyExchangeUtil.generateR(publicKey,
                sm2Possession.randomNum).getEncoded(false);

            this.namedGroup = NamedGroup.valueOf(params);
            if ((namedGroup == null) || (namedGroup.oid == null) ) {
                // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unnamed EC parameter spec: " + params);
            }

            if (gmx509Possession == null) {
                // anonymous, no authentication, no signature
                paramsSignature = null;
                signatureScheme = null;
                useExplicitSigAlgorithm = false;
            } else {
                useExplicitSigAlgorithm =
                        shc.negotiatedProtocol.useTLS12PlusSpec() && !shc.t12WithGMCipherSuite;
                Signature signer = null;
                if (useExplicitSigAlgorithm) {
                    Map.Entry<SignatureScheme, Signature> schemeAndSigner =
                            SignatureScheme.getSignerOfPreferableAlgorithm(
                                shc.peerRequestedSignatureSchemes,
                                new X509Authentication.X509Possession(
                                gmx509Possession.popSignPrivateKey, gmx509Possession.popSignCerts),
                                shc.negotiatedProtocol);
                    if (schemeAndSigner == null) {
                        // Unlikely, the credentials generator should have
                        // selected the preferable signature algorithm properly.
                        throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                                "No supported signature algorithm for " +
                                gmx509Possession.popSignPrivateKey.getAlgorithm() +
                                "  key");
                    } else {
                        signatureScheme = schemeAndSigner.getKey();
                        signer = schemeAndSigner.getValue();
                    }
                } else {
                    signatureScheme = null;
                    try {
                        signer = getSignature(
                                gmx509Possession.popSignPrivateKey.getAlgorithm(),
                                gmx509Possession.popSignPrivateKey);
                    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                        throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                            "Unsupported signature algorithm: " +
                            gmx509Possession.popSignPrivateKey.getAlgorithm(), e);
                    }
                }

                byte[] signature = null;
                try {
                    updateSignature(signer, shc.clientHelloRandom.randomBytes,
                            shc.serverHelloRandom.randomBytes,
                            curveId, publicPoint);
                    signature = signer.sign();
                } catch (SignatureException ex) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Failed to sign sm2 parameters: " +
                        gmx509Possession.popSignPrivateKey.getAlgorithm(), ex);
                }
                paramsSignature = signature;
            }
        }

        SM2ServerKeyExchangeMessage(HandshakeContext handshakeContext,
                ByteBuffer m) throws IOException {
            super(handshakeContext);

            // This happens in client side only.
            ClientHandshakeContext chc =
                    (ClientHandshakeContext)handshakeContext;

            byte curveType = (byte)Record.getInt8(m);
            if (curveType != CURVE_NAMED_CURVE) {
                // Unlikely as only the named curves should be negotiated.
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unsupported ECCurveType: " + curveType);
            }

            this.curveId = Record.getInt16(m);
            this.namedGroup = NamedGroup.SM2P256V1;
            if (curveId != 23) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unknown named group ID: " + curveId);
            }

            if (!SupportedGroups.isSupported(namedGroup)) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unsupported named group: " + namedGroup);
            }

            if (namedGroup.oid == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unknown named EC curve: " + namedGroup);
            }

            publicPoint = Record.getBytes8(m);
            if (publicPoint.length == 0) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Insufficient ECPoint data: " + namedGroup);
            }

            GMX509Credentials x509Credentials = null;
            for (SSLCredentials cd : chc.handshakeCredentials) {
                if (cd instanceof GMX509Credentials) {
                    x509Credentials = (GMX509Credentials)cd;
                    break;
                }
            }

            if (x509Credentials == null) {
                // anonymous, no authentication, no signature
                if (m.hasRemaining()) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Invalid DH ServerKeyExchange: unknown extra data");
                }
                this.signatureScheme = null;
                this.paramsSignature = null;
                this.useExplicitSigAlgorithm = false;

                return;
            }

            this.useExplicitSigAlgorithm =
                    chc.negotiatedProtocol.useTLS12PlusSpec() && !chc.t12WithGMCipherSuite;
            if (useExplicitSigAlgorithm) {
                int ssid = Record.getInt16(m);
                signatureScheme = SignatureScheme.valueOf(ssid);
                if (signatureScheme == null) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Invalid signature algorithm (" + ssid +
                        ") used in SM2 ServerKeyExchange handshake message");
                }

                if (!chc.localSupportedSignAlgs.contains(signatureScheme)) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Unsupported signature algorithm (" +
                        signatureScheme.name +
                        ") used in SM2 ServerKeyExchange handshake message");
                }
            } else {
                signatureScheme = null;
            }

            // read and verify the signature
            paramsSignature = Record.getBytes16(m);
            Signature signer;
            if (useExplicitSigAlgorithm) {
                try {
                    signer = signatureScheme.getVerifier(
                            x509Credentials.popSignPublicKey);
                } catch (NoSuchAlgorithmException | InvalidKeyException |
                        InvalidAlgorithmParameterException nsae) {
                    throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Unsupported signature algorithm: " +
                        signatureScheme.name, nsae);
                }
            } else {
                try {
                    signer = getSignature(
                            x509Credentials.popSignPublicKey.getAlgorithm(),
                            x509Credentials.popSignPublicKey);
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Unsupported signature algorithm: " +
                        x509Credentials.popSignPublicKey.getAlgorithm(), e);
                }
            }

            try {
                updateSignature(signer,
                        chc.clientHelloRandom.randomBytes,
                        chc.serverHelloRandom.randomBytes,
                        curveId, publicPoint);

                if (!signer.verify(paramsSignature)) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Invalid SM2 ServerKeyExchange signature");
                }
            } catch (SignatureException ex) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Cannot verify SM2 ServerKeyExchange signature", ex);
            }
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.SERVER_KEY_EXCHANGE;
        }

        @Override
        public int messageLength() {
            int sigLen = 0;
            if (paramsSignature != null) {
                sigLen = 2 + paramsSignature.length;
                if (useExplicitSigAlgorithm) {
                    sigLen += SignatureScheme.sizeInRecord();
                }
            }

            return 4 + publicPoint.length + sigLen;
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8(CURVE_NAMED_CURVE);
            hos.putInt16(23);
            hos.putBytes8(publicPoint);
            if (paramsSignature != null) {
                if (useExplicitSigAlgorithm) {
                    hos.putInt16(signatureScheme.id);
                }

                hos.putBytes16(paramsSignature);
            }
        }

        @Override
        public String toString() {
            if (useExplicitSigAlgorithm) {
                MessageFormat messageFormat = new MessageFormat(
                    "\"SM2 ServerKeyExchange\": '{'\n" +
                    "  \"parameters\": '{'\n" +
                    "    \"named group\": \"{0}\"\n" +
                    "    \"sm2 public\": '{'\n" +
                    "{1}\n" +
                    "    '}',\n" +
                    "  '}',\n" +
                    "  \"digital signature\":  '{'\n" +
                    "    \"signature algorithm\": \"{2}\"\n" +
                    "    \"signature\": '{'\n" +
                    "{3}\n" +
                    "    '}',\n" +
                    "  '}'\n" +
                    "'}'",
                    Locale.ENGLISH);

                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                    namedGroup.name,
                    Utilities.indent(
                            hexEncoder.encodeBuffer(publicPoint), "      "),
                    signatureScheme.name,
                    Utilities.indent(
                            hexEncoder.encodeBuffer(paramsSignature), "      ")
                };
                return messageFormat.format(messageFields);
            } else if (paramsSignature != null) {
                MessageFormat messageFormat = new MessageFormat(
                    "\"SM2 ServerKeyExchange\": '{'\n" +
                    "  \"parameters\":  '{'\n" +
                    "    \"named group\": \"{0}\"\n" +
                    "    \"sm2 public\": '{'\n" +
                    "{1}\n" +
                    "    '}',\n" +
                    "  '}',\n" +
                    "  \"signature\": '{'\n" +
                    "{2}\n" +
                    "  '}'\n" +
                    "'}'",
                    Locale.ENGLISH);

                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                    namedGroup.name,
                    Utilities.indent(
                            hexEncoder.encodeBuffer(publicPoint), "      "),
                    Utilities.indent(
                            hexEncoder.encodeBuffer(paramsSignature), "    ")
                };

                return messageFormat.format(messageFields);
            } else {    // anonymous
                MessageFormat messageFormat = new MessageFormat(
                    "\"SM2 ServerKeyExchange\": '{'\n" +
                    "  \"parameters\":  '{'\n" +
                    "    \"named group\": \"{0}\"\n" +
                    "    \"sm2 public\": '{'\n" +
                    "{1}\n" +
                    "    '}',\n" +
                    "  '}'\n" +
                    "'}'",
                    Locale.ENGLISH);

                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                    namedGroup.name,
                    Utilities.indent(
                            hexEncoder.encodeBuffer(publicPoint), "      "),
                };

                return messageFormat.format(messageFields);
            }
        }

        private static Signature getSignature(String keyAlgorithm,
                Key key) throws NoSuchAlgorithmException, InvalidKeyException {
            Signature signer = null;
            switch (keyAlgorithm) {
                case "EC":
                    signer = JsseJce.getSignature(JsseJce.SIGNATURE_SM2);
                    break;
                case "RSA":
                    signer = RSASignature.getInstance();
                    break;
                default:
                    throw new NoSuchAlgorithmException(
                        "neither an RSA or a EC key : " + keyAlgorithm);
            }

            if (signer != null) {
                if (key instanceof PublicKey) {
                    signer.initVerify((PublicKey)(key));
                } else {
                    signer.initSign((PrivateKey)key);
                }
            }

            return signer;
        }

        private static void updateSignature(Signature sig,
                byte[] clntNonce, byte[] svrNonce, int namedGroupId,
                byte[] publicPoint) throws SignatureException {
            sig.update(clntNonce);
            sig.update(svrNonce);

            sig.update(CURVE_NAMED_CURVE);
            sig.update((byte)((namedGroupId >> 8) & 0xFF));
            sig.update((byte)(namedGroupId & 0xFF));
            sig.update((byte)publicPoint.length);
            sig.update(publicPoint);
        }
    }

    /**
     * The SM2 "ServerKeyExchange" handshake message producer.
     */
    private static final
            class SM2ServerKeyExchangeProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private SM2ServerKeyExchangeProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            SM2ServerKeyExchangeMessage skem =
                    new SM2ServerKeyExchangeMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Produced SM2 ServerKeyExchange handshake message", skem);
            }

            // Output the handshake message.
            skem.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();

            // The handshake message has been delivered.
            return null;
        }
    }

    /**
     * The SM2 "ServerKeyExchange" handshake message consumer.
     */
    private static final
            class SM2ServerKeyExchangeConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private SM2ServerKeyExchangeConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            SM2ServerKeyExchangeMessage skem =
                    new SM2ServerKeyExchangeMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Consuming SM2 ServerKeyExchange handshake message", skem);
            }

            GMX509Credentials gmx509Credentials = null;
            for (SSLCredentials sslCredentials : chc.handshakeCredentials) {
                if (sslCredentials instanceof GMX509Credentials) {
                    gmx509Credentials = (GMX509Credentials)sslCredentials;
                    break;
                }
            }
            //
            // update
            //
            chc.handshakeCredentials.add(
                    new SM2Credentials((ECPublicKey) gmx509Credentials.popEncPublicKey,
                    skem.namedGroup, skem.publicPoint));

            //
            // produce
            //
            // Need no new handshake message producers here.
        }
    }
}

