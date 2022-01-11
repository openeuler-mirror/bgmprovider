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
import org.apache.tomcat.util.net.SSLUtilBase;
import org.apache.tomcat.util.net.jsse.JSSEUtil;
import org.apache.tomcat.util.res.StringManager;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPathParameters;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

public class GMJSSEUtil extends JSSEUtil {
    private static final Log log = LogFactory.getLog(GMJSSEUtil.class);
    private static final StringManager sm = StringManager.getManager(GMJSSEUtil.class);

    // validate gm keystore type , only support PKCS12 and JKS.
    private final Set<String> VALIDATE_GM_KEYSTORE_TYPE = new HashSet<>(Arrays.asList("PKCS12", "JKS"));

    // SSLUtilBase#getStore method
    private static Method getStoreMethod;

    // SSLHostConfig#getRevocationEnabled method
    private static Method getRevocationEnabledMethod;

    // SSLHostConfig#isCertificateVerificationDepthConfigured method
    private static Method isCertificateVerificationDepthConfiguredMethod;

    // SSLHostConfig
    private final SSLHostConfig sslHostConfig;

    static {
        initReflectionMethod();
    }

    /**
     * Obtain the following methods through reflection:
     * SSLUtilBase#getStore
     * SSLHostConfig#getRevocationEnabled
     * SSLHostConfig#isCertificateVerificationDepthConfigured
     */
    private static void initReflectionMethod() {
        getStoreMethod = getStoreMethod();
        getRevocationEnabledMethod = getRevocationEnabledMethod();
        isCertificateVerificationDepthConfiguredMethod = isCertificateVerificationDepthConfiguredMethod();
    }

    private static Method getStoreMethod() {
        Method method;
        try {
            method = SSLUtilBase.class.getDeclaredMethod("getStore",
                    String.class, String.class, String.class, String.class);
        } catch (NoSuchMethodException e) {
            log.warn("SSLUtilBase class does not define getStore method , " +
                    "try to call the JSSEUtil getStore method.");
            try {
                method = JSSEUtil.class.getDeclaredMethod("getStore",
                        String.class, String.class, String.class, String.class);
                log.info("Call JSSEUtil getStore method success");
            } catch (NoSuchMethodException noSuchMethodException) {
                log.error("JSSEUtil class does not define getStore method.");
                throw new InternalError(e);
            }
        }
        method.setAccessible(true);
        return method;
    }

    private static Method getRevocationEnabledMethod() {
        Method method = null;
        try {
            method = SSLHostConfig.class.getDeclaredMethod("getRevocationEnabled");
            method.setAccessible(true);
        } catch (NoSuchMethodException e) {
            log.warn("SSLHostConfig class does not define getRevocationEnabled method.");
        }
        return method;
    }

    private static Method isCertificateVerificationDepthConfiguredMethod() {
        Method method = null;
        try {
            method = SSLHostConfig.class.getDeclaredMethod("isCertificateVerificationDepthConfigured");
            method.setAccessible(true);
        } catch (NoSuchMethodException e) {
            log.warn("SSLHostConfig class does not define isCertificateVerificationDepthConfigured method.");
        }
        return method;
    }

    public GMJSSEUtil(SSLHostConfigCertificate certificate) {
        super(certificate);
        this.sslHostConfig = certificate.getSSLHostConfig();
    }

    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        String keyAlias = certificate.getCertificateKeyAlias();

        // GM key
        if (isGMKey(keyAlias)) {
            return getGMKeyManagers(keyAlias);
        }

        return super.getKeyManagers();
    }

    /**
     * Determine whether to configure GM secret key.
     * If multiple certificateKeyAlias values are configured, it means that GM key is used.
     *
     * @param keyAlias certificateKeyAlias
     */
    private boolean isGMKey(String keyAlias) {
        return keyAlias != null && keyAlias.split(",").length > 1;
    }

    /**
     * Get the GM keyManagers.
     *
     * @param keyAlias certificateKeyAlias
     */
    private KeyManager[] getGMKeyManagers(String keyAlias) throws Exception {
        String[] keyAliases = Arrays.stream(keyAlias.split(","))
                .map(s->s.trim()).toArray(String[]::new);;
        // Load keystore
        KeyStore ks;
        if (usePEMFile()) {
            // load by PEM file
            ks = loadKeyStoreByPEMFile(keyAliases);
        } else {
            // load by keystore file
            ks = loadKeyStoreByKeyStoreFile(keyAliases);
        }

        // get keyManagers
        String keyPass = certificate.getCertificateKeyPassword();
        if (keyPass == null) {
            keyPass = certificate.getCertificateKeystorePassword();
        }
        String passwd = keyPass.split(",")[0];
        String algorithm = sslHostConfig.getKeyManagerAlgorithm();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, passwd.toCharArray());
        return kmf.getKeyManagers();
    }

    /**
     * Determine whether to use the PEM file to generate the keystore.
     */
    private boolean usePEMFile() {
        if (certificate.getCertificateKeyFile() != null) {
            return true;
        }
        if (certificate.getCertificateFile() != null) {
            return true;
        }
        return certificate.getCertificateChainFile() != null;
    }

    /**
     * Parse the configured PEM file, get the privateKey and certificates and the certificate chain,
     * and then save it in the newly created keystore.
     *
     * @param keyAliases Multiple values obtained after separating the certificateKeyAlias
     *                   attribute value with a comma
     */
    private KeyStore loadKeyStoreByPEMFile(String[] keyAliases) throws IOException {
        String[] certificateFiles = getCertificateFiles();
        int certCount = certificateFiles.length;
        String[] certificateKeyFiles = getCertificateKeyFiles(certCount);
        String[] certificateChainFiles = getCertificateChainFiles(certCount);

        // If certificateKeyPassword is not set, use the CertificateKeystorePassword as the certificateKeyPassword.
        int keyCount = certificateKeyFiles.length;
        String[] keyPasswords;
        if (!isEmpty(certificate.getCertificateKeyPassword())) {
            keyPasswords = getCertificateKeyPasswords(keyCount, false);
        } else {
            keyPasswords = getCertificateKeystorePasswords(keyCount, false);
        }

        // Create a empty keystore.
        KeyStore ks = loadEmptyKeyStore("PKCS12");

        // Take the first password as the new password for all keys.
        char[] destKeyPassword = keyPasswords[0].toCharArray();

        /*
         * Parse the PEM file, get the PrivateKey and certificates and the certificate chain,
         * and then save it in the created keystore.
         */
        for (int i = 0; i < keyAliases.length; i++) {
            setKeyEntryByPEMFile(ks, keyAliases[i], certificateKeyFiles[i], certificateFiles[i],
                    certificateChainFiles[i], keyPasswords[i], destKeyPassword);
        }
        return ks;
    }

    private void setKeyEntryByPEMFile(KeyStore ks, String keyAlias, String certificateKeyFile,
                                      String certificateFile, String certificateChainFile,
                                      String certificatePassword, char[] destKeyPassword)
            throws IOException {
        log.info(String.format("Load PEM file : { \n" +
                "\tkeyAlias : %s \n" +
                "\tcertificateKeyFile : %s \n" +
                "\tcertificateFile : %s \n" +
                "\tcertificateChainFile : %s \n" +
                "}", keyAlias, certificateKeyFile, certificateFile, certificateChainFile));
        try {
            PEMFile privateKeyPEMFile = new PEMFile(certificateKeyFile, certificatePassword);
            PEMFile certificatePEMFile = new PEMFile(certificateFile);
            Collection<Certificate> chain = new ArrayList<>(privateKeyPEMFile.getCertificates());
            chain.addAll(certificatePEMFile.getCertificates());
            if (!isEmpty(certificateChainFile)) {
                PEMFile certificateChainPEMFile = new PEMFile(certificateChainFile);
                chain.addAll(certificateChainPEMFile.getCertificates());
            }
            ks.setKeyEntry(keyAlias, privateKeyPEMFile.getPrivateKey(), destKeyPassword,
                    chain.toArray(new Certificate[0]));
        } catch (IOException | GeneralSecurityException e) {
            throw new IOException(e);
        }
        log.info(String.format("Set key entry : %s", keyAlias));
    }

    /**
     * Load the configured keystore file, obtain the entry of the specified key alias from the keystore
     * and save it to a newly created keystore.
     *
     * @param keyAliases Multiple values obtained after separating the certificateKeyAlias
     *                   attribute value with a comma
     */
    private KeyStore loadKeyStoreByKeyStoreFile(String[] keyAliases)
            throws IOException {
        // Get the attribute value related to the keystore file.
        String[] storeFiles = getCertificateKeystoreFiles();
        int keyStoreCount = storeFiles.length;
        String[] storeTypes = getCertificateKeystoreType(keyStoreCount);
        for (String storeType : storeTypes) {
            if (!isValidateGMCertificateKeystoreType(storeType)) {
                throw new IllegalArgumentException("The certificateKeystoreType Only support JKS or PKCS12.");
            }
        }
        String[] storePasswords = getCertificateKeystorePasswords(keyStoreCount, true);
        String[] keyPasswords = getCertificateKeyPasswords(keyAliases.length, false);
        String[] storeProviders = getCertificateKeystoreProviders(keyStoreCount);

        // Create a empty dest keystore.
        KeyStore destKeyStore = loadEmptyKeyStore(storeTypes[0]);
        // Use the first key password or store password as the dest key password.
        char[] destKeyPassword = keyPasswords[0] != null ? keyPasswords[0].toCharArray()
                : storePasswords[0].toCharArray();

        // Load the key and import the key to the destination store.
        Set<String> keyAliasSet = new HashSet<>(Arrays.asList(keyAliases));
        for (int i = 0; i < keyStoreCount; i++) {
            // Load source keystore.
            KeyStore srcKeyStore = getStore(storeTypes[i], storeProviders[i],
                    storeFiles[i], storePasswords[i]);

            // Import the key to the destination store.
            Map<String, char[]> srcKeyPasswordMap = createSrcKeyPasswordMap(keyAliases,
                    keyPasswords, storePasswords[i]);
            importKeyStore(keyAliasSet, srcKeyStore, srcKeyPasswordMap, destKeyStore, destKeyPassword);
        }
        return destKeyStore;
    }

    /**
     * Create source keyPassword map.
     * If keyPassword was set, use the keyPassword.
     * Otherwise, use the the storePassword as the keyPassword.
     */
    private Map<String, char[]> createSrcKeyPasswordMap(String[] keyAliases, String[] keyPasswords,
                                                        String storePassword) {
        Map<String, char[]> keyPasswordMap = new HashMap<>();
        for (int i = 0; i < keyAliases.length; i++) {
            char[] keyPassChars;
            if (keyPasswords[i] != null) {
                keyPassChars = keyPasswords[i].toCharArray();
            } else {
                keyPassChars = storePassword.toCharArray();
            }
            keyPasswordMap.put(keyAliases[i], keyPassChars);
        }
        return keyPasswordMap;
    }

    /**
     * Load a empty key store.
     */
    private KeyStore loadEmptyKeyStore(String keyStoreType) throws IOException {
        KeyStore destKeyStore;
        try {
            destKeyStore = KeyStore.getInstance(keyStoreType);
            destKeyStore.load(null, null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new IOException(e);
        }
        return destKeyStore;
    }

    /**
     * Determine whether it is a valid keystore type.
     */
    private boolean isValidateGMCertificateKeystoreType(String keystoreType) {
        return VALIDATE_GM_KEYSTORE_TYPE.contains(keystoreType.toUpperCase(Locale.ENGLISH));
    }

    /**
     * Import the key of the specified entry in the source store to the destination store
     *
     * @param keyAliasSet       The alias of the store entry that needs to be loaded
     * @param srcStore          The source store
     * @param srcKeyPasswordMap The source store password
     * @param destStore         The dest store
     * @param destKeyPassword   The dest store password
     */
    private static void importKeyStore(Set<String> keyAliasSet,
                                       KeyStore srcStore, Map<String, char[]> srcKeyPasswordMap,
                                       KeyStore destStore, char[] destKeyPassword) throws IOException {
        try {
            for (Enumeration<String> e = srcStore.aliases(); e.hasMoreElements(); ) {
                String alias = e.nextElement();

                // Skip alias that are not key or not the key of the specified alias.
                if (!srcStore.isKeyEntry(alias) || !keyAliasSet.contains(alias)) {
                    log.info(String.format("Skip entry : %s.", alias));
                    continue;
                }

                // Import the key to the destination store.
                Certificate[] certs = srcStore.getCertificateChain(alias);
                if ((certs != null) && (certs.length > 0) &&
                        (certs[0] instanceof X509Certificate)) {
                    boolean hasException = false;
                    Key key = null;
                    char[] keyPassword = srcKeyPasswordMap.get(alias);
                    try {
                        key = srcStore.getKey(alias, keyPassword);
                    } catch (NoSuchAlgorithmException | UnrecoverableKeyException exception) {
                        // If the keyPassword is not right , skip the key entry.
                        hasException = true;
                        log.warn(String.format("Skip key entry : %s, %s", alias, exception.getMessage()));
                    }

                    if (!hasException) {
                        destStore.setKeyEntry(alias, key, destKeyPassword, certs);
                        log.info(String.format("Set key entry : %s.", alias));
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
    }

    /**
     * Import the source trust store to the dest trust store.
     *
     * @param srcStore          The source trust store
     * @param srcStorePassword  The source trust store password
     * @param destStore         The dest trust store
     * @param destStorePassword The dest trust store password
     */
    private static void importTrustStore(KeyStore srcStore, char[] srcStorePassword,
                                         KeyStore destStore, char[] destStorePassword) throws IOException {
        try {
            for (Enumeration<String> e = srcStore.aliases(); e.hasMoreElements(); ) {
                String alias = e.nextElement();

                // Get the key and certificates.
                if (srcStore.isCertificateEntry(alias)) {
                    Certificate cert = srcStore.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        destStore.setCertificateEntry(alias, cert);
                        log.info(String.format("Set certificate entry : %s", alias));
                    }
                } else if (srcStore.isKeyEntry(alias)) {
                    Certificate[] certs = srcStore.getCertificateChain(alias);
                    if ((certs != null) && (certs.length > 0) &&
                            (certs[0] instanceof X509Certificate)) {
                        Key key = srcStore.getKey(alias, srcStorePassword);
                        destStore.setKeyEntry(alias, key, destStorePassword, certs);
                        log.info(String.format("Set key entry : %s", alias));
                    }
                }
            }
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    /**
     * Load store according to store type , provider , path and password.
     *
     * @param type     The store type
     * @param provider The store provider
     * @param path     The store path
     * @param pass     The store password
     */
    private KeyStore getStore(String type, String provider, String path, String pass) throws IOException {
        log.info(String.format("Load store : { \n" +
                "\ttype : %s \n" +
                "\tprovider : %s \n" +
                "\tpath : %s \n" +
                "}", type, provider, path));
        try {
            return (KeyStore) getStoreMethod.invoke(this, type, provider, path, pass);
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new IOException(e);
        }
    }

    /**
     * Verify and obtain the split certificateKeyPassword or certificateKeystorePassword value.
     */
    private String[] getCertificatePassword(int count, String keyPass) {
        return getAttrValues("certificateKeyPassword or " +
                "certificateKeystorePassword", keyPass, count);
    }

    /**
     * Verify and obtain the split certificateKeystorePassword value.
     */
    private String[] getCertificateKeystorePasswords(int keyStoreCount, boolean checkEmpty) {
        return getAttrValues("certificateKeystorePassword",
                certificate.getCertificateKeystorePassword(), keyStoreCount, checkEmpty);
    }

    /**
     * Verify and obtain the split certificateKeyPassword value.
     */
    private String[] getCertificateKeyPasswords(int keyAliasCount, boolean checkEmpty) {
        return getAttrValues("certificateKeyPassword",
                certificate.getCertificateKeyPassword(), keyAliasCount, checkEmpty);
    }

    /**
     * Verify and obtain the split certificateKeystoreFile value.
     */
    private String[] getCertificateKeystoreFiles() {
        return getAttrValues("certificateKeystoreFile",
                certificate.getCertificateKeystoreFile());
    }

    /**
     * Verify and obtain the split certificateKeystoreType value.
     */
    private String[] getCertificateKeystoreType(int keyStoreCount) {
        return getAttrValues("certificateKeystoreType",
                certificate.getCertificateKeystoreType(), keyStoreCount);
    }

    /**
     * Verify and obtain the split certificateKeystoreProvider value.
     */
    private String[] getCertificateKeystoreProviders(int keyStoreCount) {
        return getAttrValues("certificateKeystoreProvider",
                certificate.getCertificateKeystoreProvider(), keyStoreCount, false);
    }

    /**
     * Verify and obtain the split certificateFile value.
     */
    private String[] getCertificateFiles() {
        return getAttrValues("certificateFile", certificate.getCertificateFile());
    }

    /**
     * Verify and obtain the split certificateKeyFile value.
     */
    private String[] getCertificateKeyFiles(int certCount) {
        String[] certificateKeyFiles;

        if (!isEmpty(certificate.getCertificateKeyFile())) {
            certificateKeyFiles = Arrays.stream(certificate.getCertificateKeyFile()
                    .split(",")).map(s->s.trim()).toArray(String[]::new);
        } else {
            // If certificateKeyFile is empty , use certificateFile as certificateKeyFile.
            certificateKeyFiles = getCertificateFiles();
        }

        // Check whether the number of keys is equal to the number of certificates
        if (certificateKeyFiles.length != certCount) {
            throw new IllegalArgumentException("The num of certificateKeyFile is not equal " + certCount);
        }

        return certificateKeyFiles;
    }

    /**
     * Verify and obtain the split certificateChainFile value.
     * If certificateChainFile.length is more than certCount , throw IllegalArgumentException.
     * If certificateChainFile.length is equal to certCount , just return.
     * If certificateChainFile.length is less than certCount , create a new array and copy the old array
     * to the new arraythe , rest of the array elements are filled with null.
     */
    private String[] getCertificateChainFiles(int certCount) {
        String[] certificateChainFiles = getAttrValues("certificateChainFile",
                certificate.getCertificateChainFile(), false);

        // throw IllegalArgumentException.
        if (certificateChainFiles.length > certCount) {
            throw new IllegalArgumentException("The num of certificateChainFile is not less than " + certCount);
        }

        // just return
        if (certificateChainFiles.length == certCount) {
            return certificateChainFiles;
        }

        // the rest of the array elements are filled with null
        String[] newChainFiles = new String[certCount];
        System.arraycopy(certificateChainFiles, 0, newChainFiles,
                0, certificateChainFiles.length);
        return newChainFiles;
    }

    private String[] getAttrValues(String attrKey, String attrValue) {
        return getAttrValues(attrKey, attrValue, true);
    }

    private String[] getAttrValues(String attrKey, String attrValue, boolean checkEmpty) {
        boolean isEmpty = isEmpty(attrValue);
        if (isEmpty && checkEmpty) {
            throw new IllegalArgumentException("The " + attrKey + " cannot be null.");
        }
        return isEmpty ? new String[0] : Arrays.stream(attrValue.split(",")).map(s->s.trim()).toArray(String[]::new);
    }

    private String[] getAttrValues(String attrKey, String attrValue, int count) {
        return getAttrValues(attrKey, attrValue, count, true);
    }

    private String[] getAttrValues(String attrKey, String attrValue, int count, boolean checkEmpty) {
        String[] attrValues = getAttrValues(attrKey, attrValue, checkEmpty);

        // If attrValues length is not equal 1 and attrValues length is not equal count throw IllegalArgumentException.
        if (attrValues.length > 1 && attrValues.length != count) {
            throw new IllegalArgumentException("The num of " + attrKey + " is not equals 1 " +
                    "or equals " + count);
        }

        // If attrValues length is equal count , return attrValues.
        if (attrValues.length == count) {
            return attrValues;
        }

        // If attrValues length is 1, create a new attrValues and fill the attrValues[0].
        String[] newAttrValues = new String[count];
        Arrays.fill(newAttrValues, attrValues.length == 0 ? null : attrValues[0]);

        return newAttrValues;
    }

    private boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }

    @Override
    public TrustManager[] getTrustManagers() throws Exception {
        String className = sslHostConfig.getTrustManagerClassName();
        if (className != null && className.length() > 0) {
            ClassLoader classLoader = getClass().getClassLoader();
            Class<?> clazz = classLoader.loadClass(className);
            if (!(TrustManager.class.isAssignableFrom(clazz))) {
                throw new InstantiationException(sm.getString(
                        "sslUtilBase.invalidTrustManagerClassName", className));
            }
            Object trustManagerObject = clazz.getConstructor().newInstance();
            TrustManager trustManager = (TrustManager) trustManagerObject;
            return new TrustManager[]{trustManager};
        }

        TrustManager[] tms = null;

        KeyStore trustStore = loadTrustStore();
        if (trustStore != null) {
            checkTrustStoreEntries(trustStore);
            String algorithm = sslHostConfig.getTruststoreAlgorithm();
            String crlf = sslHostConfig.getCertificateRevocationListFile();
            boolean revocationEnabled = getRevocationEnabled(sslHostConfig);

            if ("PKIX".equalsIgnoreCase(algorithm)) {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
                CertPathParameters params = getCertPathParameters(crlf, trustStore, revocationEnabled);
                ManagerFactoryParameters mfp = new CertPathTrustManagerParameters(params);
                tmf.init(mfp);
                tms = tmf.getTrustManagers();
            } else {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
                tmf.init(trustStore);
                tms = tmf.getTrustManagers();
                if (crlf != null && crlf.length() > 0) {
                    throw new CRLException(sm.getString("sslUtilBase.noCrlSupport", algorithm));
                }
                // Only warn if the attribute has been explicitly configured
                if (isCertificateVerificationDepthConfigured(sslHostConfig)) {
                    log.warn(sm.getString("sslUtilBase.noVerificationDepth", algorithm));
                }
            }
        }
        return tms;
    }

    private boolean getRevocationEnabled(SSLHostConfig sslHostConfig) {
        if (getRevocationEnabledMethod == null) {
            return false;
        }

        try {
            return (boolean) getRevocationEnabledMethod.invoke(sslHostConfig);
        } catch (IllegalAccessException | InvocationTargetException e) {
            log.warn("Failed to call getRevocationEnabled method of SSLHostConfig");
        }
        return false;
    }

    private boolean isCertificateVerificationDepthConfigured(SSLHostConfig sslHostConfig) {
        if (isCertificateVerificationDepthConfiguredMethod == null) {
            return false;
        }

        try {
            return (boolean) isCertificateVerificationDepthConfiguredMethod.invoke(sslHostConfig);
        } catch (IllegalAccessException | InvocationTargetException e) {
            log.warn("Failed to call isCertificateVerificationDepthConfigured method of SSLHostConfig");
        }
        return false;
    }

    private CertPathParameters getCertPathParameters(String crlf, KeyStore trustStore,
                                                     boolean revocationEnabled) throws Exception {
        PKIXBuilderParameters xparams =
                new PKIXBuilderParameters(trustStore, new X509CertSelector());
        if (crlf != null && crlf.length() > 0) {
            Collection<? extends CRL> crls = getCRLs(crlf);
            CertStoreParameters csp = new CollectionCertStoreParameters(crls);
            CertStore store = CertStore.getInstance("Collection", csp);
            xparams.addCertStore(store);
            xparams.setRevocationEnabled(true);
        } else {
            xparams.setRevocationEnabled(revocationEnabled);
        }
        xparams.setMaxPathLength(sslHostConfig.getCertificateVerificationDepth());
        return xparams;
    }

    private KeyStore loadTrustStore() throws IOException {
        String[] storeFiles = getTruststoreFiles();
        int trustStoreCount = storeFiles.length;
        if (trustStoreCount == 0) {
            return null;
        }
        String[] storeTypes = getTruststoreTypes(trustStoreCount);
        String[] storePasswords = truststorePassword(trustStoreCount);
        String[] storeProviders = getTruststoreProviders(trustStoreCount);

        // If truststore count is 1 , just load the keystore.
        if (trustStoreCount == 1) {
            return getStore(storeTypes[0], storeProviders[0],
                    storeFiles[0], storePasswords[0]);
        }
        KeyStore destKeyStore;
        char[] destStorePassword = storePasswords[0] != null ? storePasswords[0].toCharArray() : null;


        // Create a empty dest keystore.
        destKeyStore = loadEmptyKeyStore(storeTypes[0]);
        for (int i = 0; i < trustStoreCount; i++) {
            // Load the truststore file.
            KeyStore srcKeyStore = getStore(storeTypes[i], storeProviders[i],
                    storeFiles[i], storePasswords[i]);
            // Copy the key store to the dest key store.
            char[] srcStorePassword = storePasswords[i] != null ? storePasswords[i].toCharArray() : null;
            importTrustStore(srcKeyStore, srcStorePassword, destKeyStore, destStorePassword);
        }
        return destKeyStore;
    }

    /**
     * Verify and obtain the split truststoreFile value.
     */
    private String[] getTruststoreFiles() {
        return getAttrValues("truststoreFile",
                sslHostConfig.getTruststoreFile(), false);
    }

    /**
     * Verify and obtain the split truststoreType value.
     */
    private String[] getTruststoreTypes(int trustStoreCount) {
        return getAttrValues("truststoreType",
                sslHostConfig.getTruststoreType(), trustStoreCount);
    }

    /**
     * Verify and obtain the split truststoreType value.
     */
    private String[] truststorePassword(int trustStoreCount) {
        return getAttrValues("truststorePassword",
                sslHostConfig.getTruststorePassword(), trustStoreCount, false);
    }

    /**
     * Verify and obtain the split truststoreProvider value.
     */
    private String[] getTruststoreProviders(int trustStoreCount) {
        return getAttrValues("truststoreProvider",
                sslHostConfig.getTruststoreProvider(), trustStoreCount, false);
    }

    private void checkTrustStoreEntries(KeyStore trustStore) throws Exception {
        Enumeration<String> aliases = trustStore.aliases();
        if (aliases != null) {
            Date now = new Date();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (trustStore.isCertificateEntry(alias)) {
                    Certificate cert = trustStore.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        try {
                            ((X509Certificate) cert).checkValidity(now);
                        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                            String msg = sm.getString("sslUtilBase.trustedCertNotValid", alias,
                                    ((X509Certificate) cert).getSubjectDN(), e.getMessage());
                            if (log.isDebugEnabled()) {
                                log.debug(msg, e);
                            } else {
                                log.warn(msg);
                            }
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug(sm.getString("sslUtilBase.trustedCertNotChecked", alias));
                        }
                    }
                }
            }
        }
    }
}
