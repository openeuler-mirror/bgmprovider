/*
 * Copyright (c) 2003, 2018, Oracle and/or its affiliates. All rights reserved.
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
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.MessageFormat;
import java.util.Locale;
import javax.crypto.SecretKey;
import org.openeuler.sun.security.ssl.ECCKeyExchange.ECCPremasterSecret;
import org.openeuler.sun.security.ssl.SSLHandshake.HandshakeMessage;
import org.openeuler.sun.security.ssl.GMX509Authentication.GMX509Credentials;
import org.openeuler.sun.security.ssl.GMX509Authentication.GMX509Possession;
import sun.misc.HexDumpEncoder;

/**
 * Pack of the "ClientKeyExchange" handshake message.
 */
final class ECCClientKeyExchange {
    static final SSLConsumer eccHandshakeConsumer =
        new ECCClientKeyExchangeConsumer();
    static final HandshakeProducer eccHandshakeProducer =
        new ECCClientKeyExchangeProducer();

    /**
     * The ECC ClientKeyExchange handshake message.
     */
    private static final
            class ECCClientKeyExchangeMessage extends HandshakeMessage {
        final int protocolVersion;
        final byte[] encrypted;

        ECCClientKeyExchangeMessage(HandshakeContext context,
                ECCPremasterSecret premaster,
                PublicKey publicKey) throws GeneralSecurityException {
            super(context);
            this.protocolVersion = context.clientHelloVersion;
            this.encrypted = premaster.getEncoded(
                    publicKey, context.sslContext.getSecureRandom());
        }

        ECCClientKeyExchangeMessage(HandshakeContext context,
                ByteBuffer m) throws IOException {
            super(context);

            if (m.remaining() < 2) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "Invalid ECC ClientKeyExchange message: insufficient data");
            }

            this.protocolVersion = context.clientHelloVersion;
            this.encrypted = Record.getBytes16(m);
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_KEY_EXCHANGE;
        }

        @Override
        public int messageLength() {
            return encrypted.length + 2;
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes16(encrypted);
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                "\"ECC ClientKeyExchange\": '{'\n" +
                "  \"client_version\":  {0}\n" +
                "  \"encncrypted\": '{'\n" +
                "{1}\n" +
                "  '}'\n" +
                "'}'",
                Locale.ENGLISH);

            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {
                ProtocolVersion.nameOf(protocolVersion),
                Utilities.indent(
                        hexEncoder.encodeBuffer(encrypted), "    "),
            };
            return messageFormat.format(messageFields);
        }
    }

    /**
     * The ECC "ClientKeyExchange" handshake message producer.
     */
    private static final
            class ECCClientKeyExchangeProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private ECCClientKeyExchangeProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // This happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;
            GMX509Credentials gmx509Credentials = null;
            for (SSLCredentials credential : chc.handshakeCredentials) {
                if (credential instanceof GMX509Credentials) {
                    gmx509Credentials = (GMX509Credentials)credential;
                    break;
                }
            }

            if (gmx509Credentials == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "No ECC credentials negotiated for client key exchange");
            }

            PublicKey publicKey = gmx509Credentials.popEncPublicKey;
            if (!publicKey.getAlgorithm().equals("EC")) {      // unlikely
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Not ECC public key for client key exchange");
            }

            ECCPremasterSecret premaster;
            ECCClientKeyExchangeMessage ckem;
            try {
                premaster = ECCPremasterSecret.createPremasterSecret(chc);
                chc.handshakePossessions.add(premaster);
                ckem = new ECCClientKeyExchangeMessage(
                        chc, premaster, publicKey);
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Cannot generate ECC premaster secret", gse);
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Produced ECC ClientKeyExchange handshake message", ckem);
            }

            // Output the handshake message.
            ckem.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();

            // update the states
            SSLKeyExchange ke = SSLKeyExchange.valueOf(
                    chc.negotiatedCipherSuite.keyExchange,
                    chc.negotiatedProtocol);
            if (ke == null) {   // unlikely
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key exchange type");
            } else {
                SSLKeyDerivation masterKD = ke.createKeyDerivation(chc);
                SecretKey masterSecret =
                        masterKD.deriveKey("MasterSecret", null);

                // update the states
                chc.handshakeSession.setMasterSecret(masterSecret);
                SSLTrafficKeyDerivation kd =
                        SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
                if (kd == null) {   // unlikely
                    throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                            "Not supported key derivation: " +
                            chc.negotiatedProtocol);
                } else {
                    chc.handshakeKeyDerivation =
                        kd.createKeyDerivation(chc, masterSecret);
                }
            }

            // The handshake message has been delivered.
            return null;
        }
    }

    /**
     * The ECC "ClientKeyExchange" handshake message consumer.
     */
    private static final
            class ECCClientKeyExchangeConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private ECCClientKeyExchangeConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            GMX509Possession gmx509Possession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof GMX509Possession) {
                    gmx509Possession = (GMX509Possession)possession;
                    break;
                }
            }

            if (gmx509Possession == null) {  // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "No ECC possessions negotiated for client key exchange");
            }

            PrivateKey privateKey = gmx509Possession.popEncPrivateKey;
            if (!privateKey.getAlgorithm().equals("EC")) {     // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Not ECC private key for client key exchange");
            }

            ECCClientKeyExchangeMessage ckem =
                    new ECCClientKeyExchangeMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Consuming ECC ClientKeyExchange handshake message", ckem);
            }

            // create the credentials
            ECCPremasterSecret premaster;
            try {
                premaster =
                    ECCPremasterSecret.decode(shc, privateKey, ckem.encrypted);

                shc.handshakeCredentials.add(premaster);
            } catch (GeneralSecurityException gse) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Cannot decode ECC premaster secret", gse);
            }

            // update the states
            SSLKeyExchange ke = SSLKeyExchange.valueOf(
                    shc.negotiatedCipherSuite.keyExchange,
                    shc.negotiatedProtocol);
            if (ke == null) {   // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key exchange type");
            } else {
                SSLKeyDerivation masterKD = ke.createKeyDerivation(shc);
                SecretKey masterSecret =
                        masterKD.deriveKey("MasterSecret", null);

                // update the states
                shc.handshakeSession.setMasterSecret(masterSecret);
                SSLTrafficKeyDerivation kd =
                        SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
                if (kd == null) {       // unlikely
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                            "Not supported key derivation: " +
                            shc.negotiatedProtocol);
                } else {
                    shc.handshakeKeyDerivation =
                        kd.createKeyDerivation(shc, masterSecret);
                }
            }
        }
    }
}
