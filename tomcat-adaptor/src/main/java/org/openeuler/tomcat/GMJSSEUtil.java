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
import org.apache.tomcat.util.file.ConfigFileLoader;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLUtilBase;
import org.apache.tomcat.util.net.jsse.JSSEUtil;
import org.apache.tomcat.util.net.jsse.PEMFile;
import org.apache.tomcat.util.res.StringManager;
import org.apache.tomcat.util.security.KeyStoreUtil;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

public class GMJSSEUtil extends JSSEUtil {
    private static final Log log = LogFactory.getLog(GMJSSEUtil.class);
    private static final StringManager sm = StringManager.getManager(SSLUtilBase.class);
    // validate gm keystore type , only support PKCS12 and JKS.
    private final Set<String> VALIDATE_GM_KEYSTORE_TYPE = new HashSet<>(Arrays.asList("PKCS12", "JKS"));

    public GMJSSEUtil(SSLHostConfigCertificate certificate) {
        super(certificate);
    }

    public GMJSSEUtil(SSLHostConfigCertificate certificate, boolean warnOnSkip) {
        super(certificate, warnOnSkip);
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
        String[] keyAliases = keyAlias.split(",");
        String keyPass = certificate.getCertificateKeyPassword();
        if (keyPass == null) {
            keyPass = certificate.getCertificateKeystorePassword();
        }

        // Load keystore
        KeyStore ks;
        if (usePEMFile()) {
            // load by PEM file
            ks = loadKeyStoreByPEMFile(keyAliases, keyPass);
        } else {
            // load by keystore file
            ks = loadKeyStoreByKeyStoreFile(keyAliases, keyPass);
        }

        // get keyManagers
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
     * @param keyPass    The certificateKeyPassword attribute value or
     *                   certificateKeystorePassword attribute value
     */
    private KeyStore loadKeyStoreByPEMFile(String[] keyAliases, String keyPass) throws Exception {
        // Get the attribute value related to the PEM file
        String[] certificateFiles = getCertificateFiles();
        int certCount = certificateFiles.length;
        String[] certificateKeyFiles = getCertificateKeyFiles(certCount);
        String[] certificateChainFiles = getCertificateChainFiles(certCount);
        String[] keyPasswords = getCertificatePassword(certCount, keyPass);

        // Create a empty keystore.
        KeyStore ks = loadEmptyKeyStore("PKCS12");

        // Take the first password as the new password for all keys.
        char[] destKeyPasswd = keyPasswords[0].toCharArray();

        /*
         * Parse the PEM file, get the PrivateKey and certificates and the certificate chain,
         * and then save it in the created keystore.
         */
        for (int i = 0; i < keyAliases.length; i++) {
            setKeyEntryByPEMFile(ks, keyAliases[i], destKeyPasswd,
                    certificateKeyFiles[i], certificateFiles[i], certificateChainFiles[i], keyPasswords[i]);
        }
        return ks;
    }

    private void setKeyEntryByPEMFile(KeyStore ks, String keyAlias, char[] destKeyPasswd,
                                      String certificateKeyFile, String certificateFile,
                                      String certificateChainFile, String certificatePassword) throws Exception {
        log.info(String.format("Load PEM file : { \n" +
                "\tkeyAlias : %s \n" +
                "\tcertificateKeyFile : %s \n" +
                "\tcertificateFile : %s \n" +
                "\tcertificateChainFile : %s \n" +
                "}", keyAlias, certificateKeyFile, certificateFile, certificateChainFile));
        PEMFile privateKeyPEMFile = new PEMFile(certificateKeyFile, certificatePassword);
        PEMFile certificatePEMFile = new PEMFile(certificateFile);
        Collection<Certificate> chain = new ArrayList<>(privateKeyPEMFile.getCertificates());
        chain.addAll(certificatePEMFile.getCertificates());
        if (!isEmpty(certificateChainFile)) {
            PEMFile certificateChainPEMFile = new PEMFile(certificateChainFile);
            chain.addAll(certificateChainPEMFile.getCertificates());
        }
        ks.setKeyEntry(keyAlias, privateKeyPEMFile.getPrivateKey(), destKeyPasswd,
                chain.toArray(new Certificate[0]));
        log.info(String.format("Set key entry : %s", keyAlias));
    }

    /**
     * Load the configured keystore file, obtain the entry of the specified key alias from the keystore
     * and save it to a newly created keystore.
     *
     * @param keyAliases Multiple values obtained after separating the certificateKeyAlias
     *                   attribute value with a comma
     * @param keyPass    The certificateKeyPassword attribute value or
     *                   certificateKeystorePassword attribute value
     */
    private KeyStore loadKeyStoreByKeyStoreFile(String[] keyAliases, String keyPass)
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
        String[] storePasswords = getCertificatePassword(keyStoreCount, keyPass);
        String[] storeProviders = getCertificateKeystoreProviders(keyStoreCount);

        // If keystore count is 1 , just load the keystore.
        if (keyStoreCount == 1) {
            return getStore(storeTypes[0], storeProviders[0],
                    storeFiles[0], storePasswords[0]);
        }

        Set<String> keyAliasSet = new HashSet<>(Arrays.asList(keyAliases));
        KeyStore destKeyStore;
        String destStorePassword = storePasswords[0];
        try {
            // Create a empty dest keystore.
            destKeyStore = loadEmptyKeyStore(storeTypes[0]);
            for (int i = 0; i < keyStoreCount; i++) {
                // Load the keystore file.
                KeyStore srcKeyStore = getStore(storeTypes[i], storeProviders[i],
                        storeFiles[i], storePasswords[i]);
                // Copy the key store to the dest key store.
                copyStore(keyAliasSet, srcKeyStore, storePasswords[i].toCharArray(),
                        destKeyStore, destStorePassword.toCharArray());
            }
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }
        return destKeyStore;
    }

    /**
     * Load a empty key store.
     */
    private KeyStore loadEmptyKeyStore(String keyStoreType) throws Exception {
        KeyStore destKeyStore = KeyStore.getInstance(keyStoreType);
        destKeyStore.load(null, null);
        return destKeyStore;
    }

    /**
     * Determine whether it is a valid keystore type.
     */
    private boolean isValidateGMCertificateKeystoreType(String keystoreType) {
        return VALIDATE_GM_KEYSTORE_TYPE.contains(keystoreType.toUpperCase(Locale.ENGLISH));
    }

    /**
     * Copy the source store to the dest store.
     *
     * @param keyAliasSet       The alias of the store entry that needs to be loaded
     * @param srcStore          The source store
     * @param srcStorePassword  The source store password
     * @param destStore         The dest store
     * @param destStorePassword The dest store password
     */
    private static void copyStore(Set<String> keyAliasSet, KeyStore srcStore, char[] srcStorePassword,
                                  KeyStore destStore, char[] destStorePassword)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        for (Enumeration<String> e = srcStore.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();
            // If the entry name in the source keystore is not in the keyAliasSet, skip directly.
            if (keyAliasSet != null && !keyAliasSet.contains(alias)) {
                log.info(String.format("Skip entry : %s", alias));
                continue;
            }

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
    }

    /**
     * Load store according to store type , provider , path and password.
     *
     * @param type     The store type
     * @param provider The store provider
     * @param path     The store path
     * @param pass     The store password
     */
    static KeyStore getStore(String type, String provider, String path, String pass)
            throws IOException {
        log.info(String.format("Load store : { \n" +
                "\ttype : %s \n" +
                "\tprovider : %s \n" +
                "\tpath : %s \n" +
                "}", type, provider, path));
        KeyStore ks;
        InputStream istream = null;
        try {
            if (provider == null) {
                ks = KeyStore.getInstance(type);
            } else {
                ks = KeyStore.getInstance(type, provider);
            }

            if (!("PKCS11".equalsIgnoreCase(type) ||
                    path.isEmpty()) ||
                    "NONE".equalsIgnoreCase(path)) {
                istream = ConfigFileLoader.getInputStream(path);
            }

            char[] storePass = null;
            if (pass != null && (!"".equals(pass) ||
                    "JKS".equalsIgnoreCase(type) || "PKCS12".equalsIgnoreCase(type))) {
                storePass = pass.toCharArray();
            }
            KeyStoreUtil.load(ks, istream, storePass);
        } catch (IOException fnfe) {
            throw fnfe;
        } catch (Exception ex) {
            String msg = sm.getString("sslUtilBase.keystore_load_failed", type, path,
                    ex.getMessage());
            log.error(msg, ex);
            throw new IOException(msg);
        } finally {
            if (istream != null) {
                try {
                    istream.close();
                } catch (IOException ioe) {
                    // Do nothing
                }
            }
        }
        return ks;
    }

    /**
     * Verify and obtain the split certificateKeyPassword or certificateKeystorePassword value.
     */
    private String[] getCertificatePassword(int count, String keyPass) {
        return getAttrValues("certificateKeyPassword or " +
                "certificateKeystorePassword", keyPass, count);
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
            certificateKeyFiles = certificate.getCertificateKeyFile().split(",");
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
        return isEmpty ? new String[0] : attrValue.split(",");
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
            boolean revocationEnabled = sslHostConfig.getRevocationEnabled();

            if ("PKIX".equalsIgnoreCase(algorithm)) {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
                CertPathParameters params = getParameters(crlf, trustStore, revocationEnabled);
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
                if (sslHostConfig.isCertificateVerificationDepthConfigured()) {
                    log.warn(sm.getString("sslUtilBase.noVerificationDepth", algorithm));
                }
            }
        }
        return tms;
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

        try {
            // Create a empty dest keystore.
            destKeyStore = loadEmptyKeyStore(storeTypes[0]);
            for (int i = 0; i < trustStoreCount; i++) {
                // Load the truststore file.
                KeyStore srcKeyStore = getStore(storeTypes[i], storeProviders[i],
                        storeFiles[i], storePasswords[i]);
                // Copy the key store to the dest key store.
                char[] srcStorePassword = storePasswords[i] != null ? storePasswords[i].toCharArray() : null;
                copyStore(null, srcKeyStore, srcStorePassword,
                        destKeyStore, destStorePassword);
            }
        } catch (Exception e) {
            throw new IOException(e.getMessage());
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
