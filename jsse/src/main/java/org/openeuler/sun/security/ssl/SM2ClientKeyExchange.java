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
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;

import org.openeuler.sun.security.ssl.SM2KeyExchange.SM2Credentials;
import org.openeuler.sun.security.ssl.SM2KeyExchange.SM2Possession;
import org.openeuler.sun.security.ssl.SSLHandshake.HandshakeMessage;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.NamedGroup;
import org.openeuler.sun.misc.HexDumpEncoder;

/**
 * Pack of the "ClientKeyExchange" handshake message.
 */
final class SM2ClientKeyExchange {
    static final SSLConsumer sm2HandshakeConsumer =
            new SM2ClientKeyExchangeConsumer();
    static final HandshakeProducer sm2HandshakeProducer =
            new SM2ClientKeyExchangeProducer();

    /**
     * The SM2 ClientKeyExchange handshake message.
     */
    private static final
            class SM2ClientKeyExchangeMessage extends HandshakeMessage {
        private static final byte CURVE_NAMED_CURVE = (byte)0x03;
        private final byte[] encodedPoint;

        SM2ClientKeyExchangeMessage(HandshakeContext handshakeContext,
                ECPublicKey publicKey) {
            super(handshakeContext);

            ECPoint point = publicKey.getW();
            ECParameterSpec params = publicKey.getParams();
            encodedPoint = JsseJce.encodePoint(point, params.getCurve());
        }

        SM2ClientKeyExchangeMessage(HandshakeContext handshakeContext,
                ByteBuffer m) throws IOException {
            super(handshakeContext);
            // skip curve type
            Record.getInt8(m);

            // skip NamedGroup id
            Record.getInt16(m);

            if (m.remaining() != 0) {       // explicit PublicValueEncoding
                this.encodedPoint = Record.getBytes8(m);
            } else {
                this.encodedPoint = new byte[0];
            }
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_KEY_EXCHANGE;
        }

        @Override
        public int messageLength() {
            if (encodedPoint == null || encodedPoint.length == 0) {
                return 0;
            } else {
                return 1 + encodedPoint.length + 3;
            }
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8(CURVE_NAMED_CURVE);
            hos.putInt16(NamedGroup.SM2P256V1.id);
            if (encodedPoint != null && encodedPoint.length != 0) {
                hos.putBytes8(encodedPoint);
            }
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                "\"SM2 ClientKeyExchange\": '{'\n" +
                "  \"sm2 public\": '{'\n" +
                "{0}\n" +
                "  '}',\n" +
                "'}'",
                Locale.ENGLISH);
            if (encodedPoint == null || encodedPoint.length == 0) {
                Object[] messageFields = {
                    "    <implicit>"
                };
                return messageFormat.format(messageFields);
            } else {
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                    Utilities.indent(
                            hexEncoder.encodeBuffer(encodedPoint), "    "),
                };
                return messageFormat.format(messageFields);
            }
        }
    }

    /**
     * The SM2 "ClientKeyExchange" handshake message producer.
     */
    private static final
            class SM2ClientKeyExchangeProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private SM2ClientKeyExchangeProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            SM2Credentials sm2Credentials = null;
            for (SSLCredentials cd : chc.handshakeCredentials) {
                if (cd instanceof SM2Credentials) {
                    sm2Credentials = (SM2Credentials)cd;
                    break;
                }
            }

            if (sm2Credentials == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "No SM2 credentials negotiated for client key exchange");
            }

            SM2Possession sm2Possession = new SM2Possession(
                    sm2Credentials, chc.sslContext.getSecureRandom());
            chc.handshakePossessions.add(sm2Possession);
            SM2ClientKeyExchangeMessage cke =
                    new SM2ClientKeyExchangeMessage(
                            chc, sm2Possession.publicKey);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Produced SM2 ClientKeyExchange handshake message", cke);
            }

            // Output the handshake message.
            cke.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();

            // update the states
            SSLKeyExchange ke = SSLKeyExchange.valueOf(
                    chc.negotiatedCipherSuite.keyExchange,
                    chc.negotiatedProtocol);
            if (ke == null) {
                // unlikely
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key exchange type");
            } else {
                SSLKeyDerivation masterKD = ke.createKeyDerivation(chc);
                SecretKey masterSecret =
                        masterKD.deriveKey("MasterSecret", null);
                chc.handshakeSession.setMasterSecret(masterSecret);

                SSLTrafficKeyDerivation kd =
                        SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
                if (kd == null) {
                    // unlikely
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
     * The SM2 "ClientKeyExchange" handshake message consumer.
     */
    private static final
            class SM2ClientKeyExchangeConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private SM2ClientKeyExchangeConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            SM2Possession sm2Possession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof SM2Possession) {
                    sm2Possession = (SM2Possession)possession;
                    break;
                }
            }
            if (sm2Possession == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "No expected SM2 possessions for client key exchange");
            }

            ECParameterSpec params = sm2Possession.publicKey.getParams();
            NamedGroup namedGroup = NamedGroup.valueOf(params);
            if (namedGroup == null) {
                // unlikely, have been checked during cipher suite negotiation.
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unsupported EC server cert for SM2 client key exchange");
            }

            SSLKeyExchange ke = SSLKeyExchange.valueOf(
                    shc.negotiatedCipherSuite.keyExchange,
                    shc.negotiatedProtocol);
            if (ke == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key exchange type");
            }

            // parse the handshake message
            SM2ClientKeyExchangeMessage cke =
                    new SM2ClientKeyExchangeMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Consuming SM2 ClientKeyExchange handshake message", cke);
            }

            // create the credentials
            try {
                ECPoint point =
                        JsseJce.decodePoint(cke.encodedPoint, params.getCurve());
                ECPublicKeySpec spec = new ECPublicKeySpec(point, params);

                KeyFactory kf = JsseJce.getKeyFactory("EC");
                ECPublicKey peerPublicKey =
                        (ECPublicKey)kf.generatePublic(spec);

                // check constraints of peer ECPublicKey
                if (shc.algorithmConstraints != null &&
                        !shc.algorithmConstraints.permits(
                                EnumSet.of(CryptoPrimitive.KEY_AGREEMENT),
                                peerPublicKey)) {
                    throw new SSLHandshakeException(
                            "ECPublicKey does not comply to algorithm constraints");
                }

                shc.handshakeCredentials.add(new SM2Credentials(
                        peerPublicKey, namedGroup));
            } catch (GeneralSecurityException | java.io.IOException e) {
                throw (SSLHandshakeException)(new SSLHandshakeException(
                        "Could not generate ECPublicKey").initCause(e));
            }

            // update the states
            SSLKeyDerivation masterKD = ke.createKeyDerivation(shc);
            SecretKey masterSecret =
                    masterKD.deriveKey("MasterSecret", null);
            shc.handshakeSession.setMasterSecret(masterSecret);

            SSLTrafficKeyDerivation kd =
                    SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
            if (kd == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "Not supported key derivation: " + shc.negotiatedProtocol);
            } else {
                shc.handshakeKeyDerivation =
                    kd.createKeyDerivation(shc, masterSecret);
            }
        }
    }
}
