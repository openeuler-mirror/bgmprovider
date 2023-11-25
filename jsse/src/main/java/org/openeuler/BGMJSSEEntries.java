/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler;

import java.security.Provider;

class BGMJSSEEntries extends AbstractEntries {

    BGMJSSEEntries(Provider provider) {
        super(provider);
    }

    @Override
    protected void putServices(Provider provider) {
        // KeyManagerFactory
        if (BGMJSSEConfig.enableTrustManagerFactory()) {
            putKeyManagerFactory(provider);
        }

        // TrustManagerFactory
        if (BGMJSSEConfig.enableTrustManagerFactory()) {
            putTrustManagerFactory(provider);
        }

        // KeyGenerator
        if (BGMJSSEConfig.enableKeyGenerator()) {
            putKeyGenerator(provider);
        }

        // SSLContext
        if (BGMJSSEConfig.enableSSLContext()) {
            putSSLContext(provider);
        }
        
        // KeyStore
        if (BGMJSSEConfig.enableKeyStore()) {
            putKeyStore(provider);
        }
    }

    private void putKeyManagerFactory(Provider provider) {
        add(provider, "KeyManagerFactory", "SunX509",
                "org.openeuler.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
        add(provider, "KeyManagerFactory", "NewSunX509",
                "org.openeuler.sun.security.ssl.KeyManagerFactoryImpl$X509", createAliases("PKIX"));
    }

    private void putTrustManagerFactory(Provider provider) {
        add(provider, "TrustManagerFactory", "SunX509",
                "org.openeuler.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
        add(provider, "TrustManagerFactory", "PKIX",
                "org.openeuler.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory",
                createAliases("SunPKIX", "X509", "X.509"));
    }

    private void putKeyGenerator(Provider provider) {
        add(provider, "KeyGenerator", "SunTlsPrf",
                "org.openeuler.com.sun.crypto.provider.TlsPrfGenerator$V10");
        add(provider, "KeyGenerator", "SunTls12Prf",
                "org.openeuler.com.sun.crypto.provider.TlsPrfGenerator$V12");
        add(provider, "KeyGenerator", "SunTlsMasterSecret",
                "org.openeuler.com.sun.crypto.provider.TlsMasterSecretGenerator",
                createAliases("SunTls12MasterSecret", "SunTlsExtendedMasterSecret"));
        add(provider, "KeyGenerator", "SunTlsKeyMaterial",
                "org.openeuler.com.sun.crypto.provider.TlsKeyMaterialGenerator",
                createAliases("SunTls12KeyMaterial"));

        add(provider, "KeyGenerator", "GMTlsPrf",
                "org.openeuler.gm.GMTlsPrfGenerator");
        add(provider, "KeyGenerator", "GMTlsMasterSecret",
                "org.openeuler.gm.GMTlsMasterSecretGenerator");
        add(provider, "KeyGenerator", "GMTlsKeyMaterial",
                "org.openeuler.gm.GMTlsKeyMaterialGenerator");
    }

    private void putSSLContext(Provider provider) {
        add(provider, "SSLContext", "GMTLS",
                "org.openeuler.sun.security.ssl.SSLContextImpl$GMTLSContext");
        add(provider, "SSLContext", "TLSv1",
                "org.openeuler.sun.security.ssl.SSLContextImpl$TLS10Context",
                createAliases("SSLv3"));
        add(provider, "SSLContext", "TLSv1.1",
                "org.openeuler.sun.security.ssl.SSLContextImpl$TLS11Context");
        add(provider, "SSLContext", "TLSv1.2",
                "org.openeuler.sun.security.ssl.SSLContextImpl$TLS12Context");
        add(provider, "SSLContext", "TLSv1.3",
                "org.openeuler.sun.security.ssl.SSLContextImpl$TLS13Context");
        add(provider, "SSLContext", "TLS",
                "org.openeuler.sun.security.ssl.SSLContextImpl$TLSContext",
                createAliases("SSL"));
        add(provider, "SSLContext", "Default",
                "org.openeuler.sun.security.ssl.SSLContextImpl$DefaultSSLContext");
    }

    private void putKeyStore(Provider provider) {
        add(provider, "KeyStore", "PKCS12",
                "org.openeuler.gm.KeyStoreResolver$DualFormatPKCS12");
        add(provider, "KeyStore", "JKS",
                "org.openeuler.gm.KeyStoreResolver$DualFormatJKS");
    }
}
