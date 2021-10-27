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

package org.openeuler.gm;

import org.junit.Assert;
import sun.security.action.OpenFileInputStreamAction;

import java.io.FileInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessController;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

public class TestUtils {
    private static final String NONE = "NONE";

    public static String getPath(String fileName) {
        URL url = BaseTest.class.getClassLoader().getResource(fileName);
        if (url != null) {
            try {
                return new URI(url.getPath()).getPath();
            } catch (URISyntaxException e) {
                return null;
            }
        }
        return null;
    }

    public static String[] getPaths(String[] fileNames) {
        String[] expectedPaths = new String[fileNames.length];
        for (int i = 0; i < fileNames.length; i++) {
            expectedPaths[i] = getPath(fileNames[i]);
        }
        return expectedPaths;
    }

    public static String arrayToString(String[] expectedPaths) {
        StringBuilder builder = new StringBuilder();
        for (String expectedPath : expectedPaths) {
            builder.append(",").append(expectedPath);
        }
        return builder.substring(1);
    }

    public static KeyStore loadKeyStore(String storePath, String storeType,
                                        String storePassword)
            throws Exception {
        KeyStore store = KeyStore.getInstance(storeType);
        char[] password = (storePassword == null || storePassword.isEmpty()) ? null :
                storePassword.toCharArray();
        if (NONE.equals(storePath)) {
            store.load(null, password);
            return store;
        }
        try (FileInputStream fis = AccessController.doPrivileged(
                new OpenFileInputStreamAction(storePath))) {
            store.load(fis, password);
        }
        return store;
    }

    public static KeyStore[] loadKeyStores(String[] storePaths, String[] storeTypes,
                                           String[] storePasswords) throws Exception {
        Assert.assertEquals(storePaths.length, storeTypes.length);
        Assert.assertEquals(storePaths.length, storePasswords.length);
        KeyStore[] keyStores = new KeyStore[storePaths.length];
        for (int i = 0; i < keyStores.length; i++) {
            KeyStore store = loadKeyStore(storePaths[i], storeTypes[i],
                    storePasswords[i]);
            keyStores[i] = store;
        }
        return keyStores;
    }

    public static StoreInfo getStoreInfo(KeyStore store, String password) throws Exception {
        Set<X509Certificate> certs = new HashSet<>();
        Set<Credential> credentials = new HashSet<>();
        for (Enumeration<String> e = store.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();
            if (store.isCertificateEntry(alias)) {
                Certificate cert = store.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    certs.add((X509Certificate) cert);
                }
            } else if (store.isKeyEntry(alias)) {
                Certificate[] tempCerts = store.getCertificateChain(alias);
                if ((tempCerts != null) && (tempCerts.length > 0) &&
                        (tempCerts[0] instanceof X509Certificate)) {
                    Key key = store.getKey(alias, password != null ? password.toCharArray() : null);
                    Credential credential = new Credential(key, (X509Certificate[]) tempCerts);
                    credentials.add(credential);
                }
            }
        }
        return new StoreInfo(certs, credentials);
    }

    public static StoreInfo getStoreInfo(KeyStore[] stores, String[] passwords) throws Exception {
        Assert.assertEquals(stores.length, passwords.length);
        Set<X509Certificate> certs = new HashSet<>();
        Set<Credential> credentials = new HashSet<>();
        for (int i = 0; i < stores.length; i++) {
            StoreInfo storeInfo = getStoreInfo(stores[i], passwords[i]);
            certs.addAll(storeInfo.certs);
            credentials.addAll(storeInfo.credentials);
        }
        return new StoreInfo(certs, credentials);
    }

    public static class Credential {
        private X509Certificate[] certs;
        private Key key;

        Credential(Key key, X509Certificate[] certs) {
            this.key = key;
            this.certs = certs;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Credential that = (Credential) o;
            return Arrays.equals(certs, that.certs) && Objects.equals(key, that.key);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(key);
            result = 31 * result + Arrays.hashCode(certs);
            return result;
        }
    }

    public static class StoreInfo {
        Set<X509Certificate> certs;
        Set<Credential> credentials;

        public StoreInfo(Set<X509Certificate> certs, Set<Credential> credentials) {
            this.certs = certs;
            this.credentials = credentials;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            StoreInfo that = (StoreInfo) o;
            return Objects.equals(certs, that.certs) && Objects.equals(credentials, that.credentials);
        }

        @Override
        public int hashCode() {
            return Objects.hash(certs, credentials);
        }
    }
}
