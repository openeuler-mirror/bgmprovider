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
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Locale;
import org.openeuler.sun.security.ssl.SSLHandshake.HandshakeMessage;
import org.openeuler.sun.security.ssl.GMX509Authentication.GMX509Credentials;
import org.openeuler.sun.security.ssl.GMX509Authentication.GMX509Possession;
import org.openeuler.sun.misc.HexDumpEncoder;

/**
 * Pack of the ServerKeyExchange handshake message.
 */
final class ECCServerKeyExchange {
    static final SSLConsumer eccHandshakeConsumer =
        new ECCServerKeyExchangeConsumer();
    static final HandshakeProducer eccHandshakeProducer =
        new ECCServerKeyExchangeProducer();

    /**
     * The ECC ServerKeyExchange handshake message.
     *
     * Used for ECC only.
     */
    private static final
            class ECCServerKeyExchangeMessage extends HandshakeMessage {

        // signature bytes, none-null as no anonymous ECC key exchange.
        private final byte[] paramsSignature;

        // TLSv1.2 + GM cipher needs to send SignatureScheme id.
        private final boolean useExplicitSigAlgorithm;

        // the signature algorithm used by this ServerKeyExchange message
        private final SignatureScheme signatureScheme;

        private ECCServerKeyExchangeMessage(HandshakeContext handshakeContext,
                                            GMX509Possession gmx509Possession)
                throws IOException {
            super(handshakeContext);

            // This happens in server side only.
            ServerHandshakeContext shc =
                    (ServerHandshakeContext)handshakeContext;

            this.useExplicitSigAlgorithm = shc.t12WithGMCipherSuite;
            if (useExplicitSigAlgorithm) {
                if (shc.peerRequestedSignatureSchemes == null ||
                        !shc.peerRequestedSignatureSchemes.contains(SignatureScheme.ECDSA_SM3)) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                            "No supported signature algorithm");
                }
                this.signatureScheme = SignatureScheme.ECDSA_SM3;
            } else {
                this.signatureScheme = null;
            }

            byte[] signature;
            try {
                Signature signer = Signature.getInstance("SM3withSM2");
                signer.initSign(gmx509Possession.popSignPrivateKey,
                        shc.sslContext.getSecureRandom());
                updateSignature(signer,
                        shc.clientHelloRandom.randomBytes,
                        shc.serverHelloRandom.randomBytes,
                        gmx509Possession.popEncCerts[0]);
                signature = signer.sign();
            } catch (NoSuchAlgorithmException |
                    InvalidKeyException | SignatureException ex) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Failed to sign ECC parameters", ex);
            }

            this.paramsSignature = signature;

        }

        ECCServerKeyExchangeMessage(HandshakeContext handshakeContext,
                ByteBuffer m) throws IOException {
            super(handshakeContext);

            // This happens in client side only.
            ClientHandshakeContext chc =
                    (ClientHandshakeContext)handshakeContext;

            GMX509Credentials gmx509Credentials = null;
            for (SSLCredentials cd : chc.handshakeCredentials) {
                if (cd instanceof GMX509Credentials) {
                    gmx509Credentials = (GMX509Credentials)cd;
                    break;
                }
            }

            if (gmx509Credentials == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "No ECC credentials negotiated for server key exchange");
            }

            this.useExplicitSigAlgorithm = chc.t12WithGMCipherSuite;
            if (useExplicitSigAlgorithm) {
                int ssid = Record.getInt16(m);
                signatureScheme = SignatureScheme.valueOf(ssid);

                // If the signatureScheme is null or signatureScheme is not ECDSA_SM3
                if (signatureScheme == null || signatureScheme != SignatureScheme.ECDSA_SM3) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Invalid signature algorithm (" + ssid +
                                    ") used in ECC ServerKeyExchange handshake message");
                }

                if (!chc.localSupportedSignAlgs.contains(signatureScheme)) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Unsupported signature algorithm (" +
                                    signatureScheme.name +
                                    ") used in ECC ServerKeyExchange handshake message");
                }
            }else {
                signatureScheme = null;
            }

            this.paramsSignature = Record.getBytes16(m);

            try {
                Signature signer = Signature.getInstance("SM3withSM2");
                signer.initVerify(gmx509Credentials.popSignPublicKey);
                updateSignature(signer,
                          chc.clientHelloRandom.randomBytes,
                          chc.serverHelloRandom.randomBytes, gmx509Credentials.popEncCerts[0]);
                if (!signer.verify(paramsSignature)) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Invalid signature of ECC ServerKeyExchange message");
                }
            } catch (NoSuchAlgorithmException |
                    InvalidKeyException | SignatureException ex) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "Failed to sign ECC parameters", ex);
            }
        }

        @Override
        SSLHandshake handshakeType() {
            return SSLHandshake.SERVER_KEY_EXCHANGE;
        }

        @Override
        int messageLength() {
            int sigLen = 2 + this.paramsSignature.length;;
            if (this.useExplicitSigAlgorithm) {
                sigLen += SignatureScheme.sizeInRecord();
            }
            return sigLen;
        }

        @Override
        void send(HandshakeOutStream hos) throws IOException {
            if (this.useExplicitSigAlgorithm) {
                hos.putInt16(signatureScheme.id);
            }
            hos.putBytes16(paramsSignature);
        }

        @Override
        public String toString() {
            if (useExplicitSigAlgorithm) {
                MessageFormat messageFormat = new MessageFormat(
                        "\"ECDH ServerKeyExchange\": '{'\n" +
                                "  \"digital signature\":  '{'\n" +
                                "    \"signature algorithm\": \"{0}\"\n" +
                                "    \"signature\": '{'\n" +
                                "{1}\n" +
                                "    '}',\n" +
                                "  '}'\n" +
                                "'}'",
                        Locale.ENGLISH);

                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                        signatureScheme.name,
                        Utilities.indent(
                                hexEncoder.encodeBuffer(paramsSignature), "      ")
                };
                return messageFormat.format(messageFields);

            } else {
                MessageFormat messageFormat = new MessageFormat(
                        "\"ECC ServerKeyExchange\": '{'\n" +
                                "  \"digital signature\":  '{'\n" +
                                "    \"signature\": '{'\n" +
                                "{0}\n" +
                                "    '}',\n" +
                                "  '}'\n" +
                                "'}'",
                        Locale.ENGLISH);

                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                        Utilities.indent(
                                hexEncoder.encodeBuffer(paramsSignature), "      ")
                };
                return messageFormat.format(messageFields);
            }
        }

        /*
         * Hash the nonces and the ECC cert.
         */
        private void updateSignature(Signature signature,
                byte[] clntNonce, byte[] svrNonce, X509Certificate enc) throws SignatureException {
            signature.update(clntNonce);
            signature.update(svrNonce);

            byte[] encoded;
            try {
                encoded = enc.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new SignatureException(e);
            }
            int len = encoded.length;
            signature.update((byte)(len >> 16 & 0x0ff));
            signature.update((byte)(len >> 8 & 0x0ff));
            signature.update((byte)(len & 0x0ff));
            signature.update(encoded);
        }
    }

    /**
     * The ECC "ServerKeyExchange" handshake message producer.
     */
    private static final
            class ECCServerKeyExchangeProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private ECCServerKeyExchangeProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            GMX509Possession gmx509Possession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof GMX509Possession) {
                    gmx509Possession = (GMX509Possession)possession;
                    if (gmx509Possession != null) {
                        break;
                    }
                }
            }

            if (gmx509Possession == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "No ECC certificate negotiated for server key exchange");
            }

            ECCServerKeyExchangeMessage skem =
                    new ECCServerKeyExchangeMessage(
                            shc, gmx509Possession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Produced ECC ServerKeyExchange handshake message", skem);
            }

            // Output the handshake message.
            skem.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();

            // The handshake message has been delivered.
            return null;
        }
    }

    /**
     * The ECC "ServerKeyExchange" handshake message consumer.
     */
    private static final
            class ECCServerKeyExchangeConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private ECCServerKeyExchangeConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            ECCServerKeyExchangeMessage skem =
                    new ECCServerKeyExchangeMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Consuming ECC ServerKeyExchange handshake message", skem);
            }

            //
            // produce
            //
            // Need no new handshake message producers here.
        }
    }
}

