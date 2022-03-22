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

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

import java.lang.reflect.Field;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * JSSEImplementation support GMTLS
 */
public class GMJSSEImplementation extends JSSEImplementation {

    private static final Log log = LogFactory.getLog(GMJSSEImplementation.class);
    // GM TLS protocol version
    private static final String GM_PROTOCOL = "GMTLS";

    // cipher separator
    private static final String SEPARATOR = ":|,| ";

    // 'high' encryption cipher suites
    private static final String HIGH = "HIGH";

    /**
     * If ! is used then the ciphers are permanently deleted from the list.
     * The ciphers deleted can never reappear in the list, even if they are explicitly stated.
     */
    private static final String EXCLUDE = "!";

    /**
     * If - is used then the ciphers are deleted from the list,
     * but some or all of the ciphers can be added again by later
     * options.
     */
    private static final String DELETE = "-";

    // cipher expression represents all cipher
    private static final String ALL = "ALL";
    private static final Set<String> GM_CIPHERS_NAME_SET = new HashSet<>();
    private static final Map<String, List<String>> ALIAS_MAP = new HashMap<>();

    /* Set the provider class through the system property 'tomcat.gmtls.providers',
     * and multiple providers are separated by commas
     */
    private static final String gmtlsProviders = System.getProperty("tomcat.gmtls.providers", "org.openeuler.BGMProvider");

    private Set<String> explicitlyRequestedProtocols;

    static {
        initProvider();
        initGMCiphersNameSetAndAliasMap();
    }

    enum GMCipherGroup {
        GM_ECC,
        GM_ECDHE
    }

    enum GMCipher {
        ECC_SM4_CBC_SM3("ECC_SM4_CBC_SM3", "ECC_SM4_SM3", GMCipherGroup.GM_ECC),
        ECDHE_SM4_CBC_SM3("ECDHE_SM4_CBC_SM3", "ECDHE_SM4_SM3", GMCipherGroup.GM_ECDHE),
        ECC_SM4_GCM_SM3("ECC_SM4_GCM_SM3", GMCipherGroup.GM_ECC),
        ECDHE_SM4_GCM_SM3("ECDHE_SM4_GCM_SM3", GMCipherGroup.GM_ECDHE);
        final String cipherName;
        final String aliasCipherName;
        final GMCipherGroup cipherGroup;

        GMCipher(String cipherName, GMCipherGroup cipherGroup) {
            this(cipherName, "", cipherGroup);
        }

        GMCipher(String cipherName, String aliasCipherName, GMCipherGroup cipherGroup) {
            this.cipherName = cipherName;
            this.aliasCipherName = aliasCipherName;
            this.cipherGroup = cipherGroup;
        }
    }

    private static void initProvider() {
        String[] providerClasses = Arrays.stream(gmtlsProviders.split(",")).map(s -> s.trim()).toArray(String[]::new);
        for (int i = providerClasses.length - 1; i >= 0; i--) {
            String clazz = providerClasses[i];
            if (clazz == null || clazz.trim().isEmpty()) {
                continue;
            }
            try {
                ClassLoader classLoader = GMJSSEImplementation.class.getClassLoader();
                Class<?> providerClass = classLoader.loadClass(clazz);
                Object bgmProvider = providerClass.getDeclaredConstructor().newInstance();
                Security.insertProviderAt((Provider) bgmProvider, 1);
            } catch (Exception ex) {
                log.warn("Failed to initialize provider: " + clazz, ex);
            }
        }
    }

    private static void initGMCiphersNameSetAndAliasMap() {
        GMCipher[] gmCiphers = GMCipher.values();
        for (GMCipher gmCipher : gmCiphers) {
            GM_CIPHERS_NAME_SET.add(gmCipher.cipherName);

            // cipherName
            List<String> aliasCiphers = ALIAS_MAP.computeIfAbsent(gmCipher.cipherName, k -> new ArrayList<>());
            aliasCiphers.add(gmCipher.cipherName);

            // aliasCipherName
            if (!gmCipher.aliasCipherName.isEmpty()) {
                aliasCiphers = ALIAS_MAP.computeIfAbsent(gmCipher.aliasCipherName, k -> new ArrayList<>());
                aliasCiphers.add(gmCipher.cipherName);
            }

            // cipherGroup
            aliasCiphers = ALIAS_MAP.computeIfAbsent(gmCipher.cipherGroup.name(),
                    k -> new ArrayList<>());
            aliasCiphers.add(gmCipher.cipherName);
        }
    }

    public GMJSSEImplementation() {
        super();
    }

    @Override
    public SSLUtil getSSLUtil(SSLHostConfigCertificate certificate) {
        SSLHostConfig sslHostConfig = certificate.getSSLHostConfig();
        initGMProtocol(sslHostConfig);
        initGMCipherSuites(sslHostConfig);
        return new GMJSSEUtil(certificate);
    }

    /**
     * init GM protocol
     */
    private void initGMProtocol(SSLHostConfig sslHostConfig) {
        if (needAddGMProtocol(sslHostConfig)) {
            sslHostConfig.getProtocols().add(GM_PROTOCOL);
        }
    }

    @SuppressWarnings(value = "unchecked")
    private Set<String> getExplicitlyRequestedProtocol(SSLHostConfig sslHostConfig) {
        if (explicitlyRequestedProtocols != null) {
            return explicitlyRequestedProtocols;
        }
        Field field;
        try {
            field = sslHostConfig.getClass().getDeclaredField("explicitlyRequestedProtocols");
            field.setAccessible(true);
            explicitlyRequestedProtocols = (Set<String>) field.get(sslHostConfig);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            log.warn("The explicitlyRequestedProtocols field is not defined in the SSLHostConfig class.");
            explicitlyRequestedProtocols = new HashSet<>();
        }
        return explicitlyRequestedProtocols;
    }

    /**
     * If explicitlyRequestedProtocol is empty, it means that SSLHostConfig does not set the protocols property
     * or the Connector does not set the sslEnabledProtocols property explicitly.
     * <p>
     * The SSLHostConfig#protocols are set to SSLHostConfig#SSL_PROTO_ALL_SET and SSLHostConfig#SSL_PROTO_ALL_SET
     * does not contain GMTLS, we need to add GMTLS protocol.
     */
    private boolean needAddGMProtocol(SSLHostConfig sslHostConfig) {
        Set<String> explicitlyRequestedProtocol = getExplicitlyRequestedProtocol(sslHostConfig);
        return explicitlyRequestedProtocol.isEmpty();
    }

    /**
     * Init GM cipher suites
     */
    private void initGMCipherSuites(SSLHostConfig sslHostConfig) {
        String ciphers = sslHostConfig.getCiphers();
        Set<String> gmCiphers = parseCiphers(ciphers);
        sslHostConfig.getJsseCipherNames().addAll(gmCiphers);
        log.info("gmCiphers = " + gmCiphers);
    }

    /**
     * Parse cipher expression
     */
    private Set<String> parseCiphers(String expression) {
        String[] elements = expression.split(SEPARATOR);
        Set<String> gmCiphers = new HashSet<>();
        Set<String> removedCiphers = new HashSet<>();
        for (String element : elements) {
            parseCipher(element, gmCiphers, removedCiphers);
        }
        gmCiphers.removeAll(removedCiphers);
        log.info("Remove cipher suites : " + removedCiphers);
        return gmCiphers;
    }

    /**
     * Parse cipher expression, refer to OpenSSLCipherConfigurationParser#parse.
     * Only support DELETE and EXCLUDE now , TO_END and END are not supported.
     * For example :
     * <p>
     * ECC_SM4_CBC_SM3
     * ALL:-ECC_SM4_CBC_SM3
     * ALL:!ECC_SM4_CBC_SM3
     * GM_ECC:GM_ECDH
     * ALL:!GM_ECC
     * ALL:!GM_ECDHE
     *
     * @see org.apache.tomcat.util.net.openssl.ciphers.OpenSSLCipherConfigurationParser#parse(String)
     */
    private void parseCipher(String element, Set<String> gmCiphers, Set<String> removedCiphers) {
        if (ALIAS_MAP.containsKey(element)) {
            List<String> aliasCiphers = ALIAS_MAP.get(element);
            gmCiphers.addAll(aliasCiphers);
            log.info("Add cipher suites : " + aliasCiphers);
        } else if (element.equals(HIGH) || element.equals(ALL)) {
            gmCiphers.addAll(GM_CIPHERS_NAME_SET);
            log.info("Add cipher suites :" + GM_CIPHERS_NAME_SET);
        } else if (element.startsWith(DELETE)) {
            String alias = element.substring(1);
            if (ALIAS_MAP.containsKey(alias)) {
                List<String> aliasCiphers = ALIAS_MAP.get(alias);
                aliasCiphers.forEach(gmCiphers::remove);
                log.info("Remove cipher suites : " + aliasCiphers);
            }
        } else if (element.startsWith(EXCLUDE)) {
            String alias = element.substring(1);
            if (ALIAS_MAP.containsKey(alias)) {
                List<String> aliasCiphers = ALIAS_MAP.get(alias);
                removedCiphers.addAll(aliasCiphers);
            }
        } // else skip
    }
}
