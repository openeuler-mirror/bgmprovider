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

package org.openeuler;

import java.io.*;
import java.security.Provider;
import java.util.Map;
import java.util.Properties;

public class BGMJSSEProvider extends Provider {
    public BGMJSSEProvider() {
        super("BGMJSSEProvider", 1.8d, "BGMJSSEProvider");

        putEntries(this);
    }

    private static Properties getProp() {
        Properties props = new Properties();
        String bgmproviderConf = System.getProperty("bgmprovider.conf");
        if (bgmproviderConf == null) {
            return props;
        }

        File propFile = new File(bgmproviderConf);
        if (propFile.exists()) {
            try (InputStream is = new BufferedInputStream(new FileInputStream(propFile))) {
                props.load(is);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return props;
    }

    static void putEntries(Map<Object, Object> map) {
        Properties props = getProp();
        if (!"false".equalsIgnoreCase(props.getProperty("jsse.keyManagerFactory"))) {
            putKeyManagerFactory(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jsse.trustManagerFactory"))) {
            putTrustManagerFactory(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jsse.keyGenerator"))) {
            putKeyGenerator(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jsse.sslContext"))) {
            putSSLContext(map);
        }
    }

    private static void putKeyManagerFactory(Map<Object, Object> map) {
        map.put("KeyManagerFactory.SunX509", "org.openeuler.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
        map.put("KeyManagerFactory.NewSunX509", "org.openeuler.sun.security.ssl.KeyManagerFactoryImpl$X509");
        map.put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");
    }

    private static void putTrustManagerFactory(Map<Object, Object> map) {
        map.put("TrustManagerFactory.SunX509", "org.openeuler.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
        map.put("TrustManagerFactory.PKIX", "org.openeuler.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory");
        map.put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
        map.put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
        map.put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");
    }

    private static void putKeyGenerator(Map<Object, Object> map) {
        map.put("KeyGenerator.SunTlsPrf", "org.openeuler.com.sun.crypto.provider.TlsPrfGenerator$V10");
        map.put("KeyGenerator.SunTls12Prf", "org.openeuler.com.sun.crypto.provider.TlsPrfGenerator$V12");

        map.put("KeyGenerator.SunTlsMasterSecret", "org.openeuler.com.sun.crypto.provider.TlsMasterSecretGenerator");
        map.put("Alg.Alias.KeyGenerator.SunTls12MasterSecret", "SunTlsMasterSecret");
        map.put("Alg.Alias.KeyGenerator.SunTlsExtendedMasterSecret", "SunTlsMasterSecret");

        map.put("KeyGenerator.GMTlsPrf", "org.openeuler.gm.GMTlsPrfGenerator");
        map.put("KeyGenerator.GMTlsMasterSecret", "org.openeuler.gm.GMTlsMasterSecretGenerator");
        map.put("KeyGenerator.GMTlsKeyMaterial", "org.openeuler.gm.GMTlsKeyMaterialGenerator");

        map.put("KeyGenerator.SunTlsKeyMaterial", "org.openeuler.com.sun.crypto.provider.TlsKeyMaterialGenerator");
        map.put("Alg.Alias.KeyGenerator.SunTls12KeyMaterial", "SunTlsKeyMaterial");
    }

    private static void putSSLContext(Map<Object, Object> map) {
        map.put("SSLContext.GMTLS", "org.openeuler.sun.security.ssl.SSLContextImpl$GMTLSContext");
        map.put("SSLContext.TLSv1.1", "org.openeuler.sun.security.ssl.SSLContextImpl$TLS11Context");
        map.put("SSLContext.TLSv1.2", "org.openeuler.sun.security.ssl.SSLContextImpl$TLS12Context");
        map.put("SSLContext.TLSv1.3", "org.openeuler.sun.security.ssl.SSLContextImpl$TLS13Context");
        map.put("SSLContext.TLS", "org.openeuler.sun.security.ssl.SSLContextImpl$TLSContext");
        map.put("SSLContext.Default", "org.openeuler.sun.security.ssl.SSLContextImpl$DefaultSSLContext");
        map.put("Alg.Alias.SSLContext.SSLv3", "TLSv1");
        map.put("Alg.Alias.SSLContext.SSL", "TLS");
    }

}
