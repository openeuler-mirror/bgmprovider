/*
 * Copyright (c) 2018, 2020, Oracle and/or its affiliates. All rights reserved.
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

import javax.net.ssl.X509ExtendedKeyManager;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Map;

import org.openeuler.gm.GMConstants;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.NamedGroup;
import org.openeuler.sun.security.ssl.SupportedGroupsExtension.SupportedGroups;

enum GMX509Authentication implements SSLAuthentication {
    // Require SM2 (EC) public key
    SM2("SM2", new GMX509PossessionGenerator(new String[]{"SM2"}));

    final String keyType;
    final SSLPossessionGenerator possessionGenerator;

    GMX509Authentication(String keyType,
                         SSLPossessionGenerator possessionGenerator) {
        this.keyType = keyType;
        this.possessionGenerator = possessionGenerator;
    }

    @Override
    public SSLHandshake[] getRelatedHandshakers(
            HandshakeContext handshakeContext) {
        return new SSLHandshake[]{
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_REQUEST
        };
    }

    @SuppressWarnings({"unchecked"})
    @Override
    public Map.Entry<Byte, HandshakeProducer>[] getHandshakeProducers(
            HandshakeContext handshakeContext) {
        return (Map.Entry<Byte, HandshakeProducer>[]) (new Map.Entry[]{
                new SimpleImmutableEntry<Byte, HandshakeProducer>(
                        SSLHandshake.CERTIFICATE.id,
                        SSLHandshake.CERTIFICATE
                )
        });
    }

    @Override
    public SSLPossession createPossession(HandshakeContext handshakeContext) {
        return possessionGenerator.createPossession(handshakeContext);
    }

    private static final class GMX509PossessionGenerator implements SSLPossessionGenerator {
        private final String[] keyTypes;

        GMX509PossessionGenerator(String[] keyTypes) {
            this.keyTypes = keyTypes;
        }

        @Override
        public SSLPossession createPossession(HandshakeContext context) {
            if (context.sslConfig.isClientMode) {
                for (String keyType : keyTypes) {
                    SSLPossession poss = createClientPossession(
                            (ClientHandshakeContext) context, keyType);
                    if (poss != null) {
                        return poss;
                    }
                }
            } else {
                for (String keyType : keyTypes) {
                    SSLPossession poss = createServerPossession(
                            (ServerHandshakeContext) context, keyType);
                    if (poss != null) {
                        return poss;
                    }
                }
            }
            return null;
        }

        private SSLPossession createClientPossession(
                ClientHandshakeContext chc, String keyType) {
            X509ExtendedKeyManager km = chc.sslContext.getX509KeyManager();
            String[] clientAliases = km.getClientAliases(keyType,
                    chc.peerSupportedAuthorities == null ? null : chc.peerSupportedAuthorities.clone());

            if (clientAliases == null || clientAliases.length < 2) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest("No X.509 cert selected for " + keyType);
                }
                return null;
            }

            return createGMX509Possession(keyType, clientAliases, km, chc, true);
        }

        private SSLPossession createServerPossession(
                ServerHandshakeContext shc, String keyType) {
            X509ExtendedKeyManager km = shc.sslContext.getX509KeyManager();
            String[] serverAliases = km.getServerAliases(keyType,
                    shc.peerSupportedAuthorities == null ? null : shc.peerSupportedAuthorities.clone());

            if (serverAliases == null || serverAliases.length < 2) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest("No X.509 cert selected for " + keyType);
                }
                return null;
            }

            return createGMX509Possession(keyType, serverAliases, km, shc, false);
        }

        private GMX509Possession createGMX509Possession(String keyType, String[] serverAliases,
                                                        X509ExtendedKeyManager km, HandshakeContext shc ,
                                                        boolean isClientMode) {
            PrivateKey signPrivateKey = null;
            X509Certificate[] signCerts = null;
            PrivateKey encPrivateKey = null;
            X509Certificate[] encCerts = null;
            boolean isValid = false;
            for (String serverAlias : serverAliases) {
                PrivateKey serverPrivateKey = km.getPrivateKey(serverAlias);
                if (serverPrivateKey == null) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.finest(serverAlias + " is not a private key entry");
                    }
                    continue;
                }

                X509Certificate[] serverCerts = km.getCertificateChain(serverAlias);
                if ((serverCerts == null) || (serverCerts.length == 0)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.finest(serverAlias + " is not a certificate entry");
                    }
                    continue;
                }

                PublicKey serverPublicKey = serverCerts[0].getPublicKey();
                if ((!GMConstants.equalsAlgorithm(keyType, serverPrivateKey.getAlgorithm()))
                        || (!GMConstants.equalsAlgorithm(keyType, serverPublicKey.getAlgorithm()))) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.fine(serverAlias + " private or public key is not of " +
                                keyType + " algorithm");
                    }
                    return null;
                }

                // Determine whether NamedGroup is valid
                if (!isClientMode && GMConstants.SM2.equals(keyType)
                        && !isValidNamedGroup(serverAlias, serverPublicKey, shc)) {
                    continue;
                }

                // Choose signing and encryption
                if (isSignCert(serverCerts[0]) && signCerts == null) {
                    signPrivateKey = serverPrivateKey;
                    signCerts = serverCerts;
                } else if (isEncCert(serverCerts[0]) && encCerts == null) {
                    encPrivateKey = serverPrivateKey;
                    encCerts = serverCerts;
                } else {
                    continue;
                }

                // Determine whether it is a valid double certificate
                if (isValidDoubleCertificate(signCerts, encCerts)) {
                    isValid = true;
                    break;
                }
            }

            return isValid ? new GMX509Possession(signPrivateKey, signCerts, encPrivateKey, encCerts) : null;
        }

        // Determine whether NamedGroup is valid
        private boolean isValidNamedGroup(String alias, PublicKey publicKey, HandshakeContext shc) {
            if (!(publicKey instanceof ECPublicKey)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning(alias +
                            " public key is not an instance of ECPublicKey");
                }
                return false;
            }

            // For ECC certs, check whether we support the EC domain
            // parameters.  If the client sent a supported_groups
            // ClientHello extension, check against that too for GMTLS
            ECParameterSpec params =
                    ((ECPublicKey) publicKey).getParams();
            NamedGroup namedGroup = NamedGroup.valueOf(params);
            if ((namedGroup == null) ||
                    (!SupportedGroups.isSupported(namedGroup)) ||
                    (!namedGroup.isAvailable(shc.negotiatedProtocol)) ||
                    ((shc.clientRequestedNamedGroups != null) &&
                            !shc.clientRequestedNamedGroups.contains(namedGroup))) {

                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning(
                            "Unsupported named group (" + namedGroup +
                                    ") used in the " + alias + " certificate");
                }
                return false;
            }
            return true;
        }

        // Determine whether it is a valid double certificate
        private boolean isValidDoubleCertificate(X509Certificate[] signCerts, X509Certificate[] encCerts) {
            return signCerts != null && encCerts != null;
        }

        // Determine whether it is a signed certificate
        private boolean isSignCert(X509Certificate certificate) {
            boolean[] keyUsage = certificate.getKeyUsage();
            return keyUsage != null && keyUsage[0];
        }

        // Determine whether it is an encryption certificate
        private boolean isEncCert(X509Certificate certificate) {
            boolean[] keyUsage = certificate.getKeyUsage();
            if (keyUsage == null) {
                return false;
            }
            return keyUsage[2] || keyUsage[3] || keyUsage[4];
        }
    }

    static final class GMX509Possession implements SSLPossession {
        // sign private key
        final PrivateKey popSignPrivateKey;

        // sign certificates
        final X509Certificate[] popSignCerts;

        // enc private key
        final PrivateKey popEncPrivateKey;

        // enc certificates
        final X509Certificate[] popEncCerts;

        GMX509Possession(PrivateKey popSignPrivateKey, X509Certificate[] popSignCerts,
                         PrivateKey popEncPrivateKey, X509Certificate[] popEncCerts) {
            this.popSignCerts = popSignCerts;
            this.popSignPrivateKey = popSignPrivateKey;
            this.popEncCerts = popEncCerts;
            this.popEncPrivateKey = popEncPrivateKey;
        }
    }

    static final class GMX509Credentials implements SSLCredentials {
        // sign public key
        final PublicKey popSignPublicKey;

        // sign certificates
        final X509Certificate[] popSignCerts;

        // enc public key
        final PublicKey popEncPublicKey;

        // enc certificates
        final X509Certificate[] popEncCerts;

        public GMX509Credentials(PublicKey popSignPublicKey, X509Certificate[] popSignCerts,
                                 PublicKey popEncPublicKey, X509Certificate[] popEncCerts) {
            this.popSignPublicKey = popSignPublicKey;
            this.popSignCerts = popSignCerts;
            this.popEncPublicKey = popEncPublicKey;
            this.popEncCerts = popEncCerts;
        }
    }
}
