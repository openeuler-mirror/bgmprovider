package org.openeuler.gm;

import org.openeuler.sun.security.ssl.SSLLogger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.io.FileInputStream;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedExceptionAction;
import java.util.*;

public class KeyStoreManager {
    private static final String P11KEYSTORE = "PKCS11";
    private static final String NONE = "NONE";

    private static final class KeyStoreDescriptor {
        // the trust store name
        private final String storeName;

        // the trust store type, JKS/PKCS12
        private final String storeType;

        // the provider of the trust store
        private final String storeProvider;

        // the password used for the trust store
        private final String storePassword;

        private KeyStoreDescriptor(String storeName, String storeType,
                                   String storeProvider, String storePassword) {
            this.storeName = storeName;
            this.storeType = storeType;
            this.storeProvider = storeProvider;
            this.storePassword = storePassword;
        }

        private static List<KeyStoreDescriptor> createInstances() throws Exception {
            final Map<String, String> props = new HashMap<>();
            AccessController.doPrivileged(
                    new PrivilegedExceptionAction<Object>() {
                        @Override
                        public Object run() throws Exception {
                            props.put("keyStore", System.getProperty(
                                    "javax.net.ssl.keyStore", ""));
                            props.put("keyStoreType", System.getProperty(
                                    "javax.net.ssl.keyStoreType",
                                    KeyStore.getDefaultType()));
                            props.put("keyStoreProvider", System.getProperty(
                                    "javax.net.ssl.keyStoreProvider", ""));
                            props.put("keyStorePasswd", System.getProperty(
                                    "javax.net.ssl.keyStorePassword", ""));
                            return null;
                        }
                    });

            final String defaultKeyStore = props.get("keyStore");
            String defaultKeyStoreType = props.get("keyStoreType");
            String defaultKeyStoreProvider = props.get("keyStoreProvider");
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                SSLLogger.fine("keyStore is : " + defaultKeyStore);
                SSLLogger.fine("keyStore type is : " +
                        defaultKeyStoreType);
                SSLLogger.fine("keyStore provider is : " +
                        defaultKeyStoreProvider);
            }
            String defaultKeyStorePasswd = props.get("keyStorePasswd");

            // Check and handle props
            String[] storeNames = defaultKeyStore.isEmpty() ? new String[0] : defaultKeyStore.split(",");
            String[] storeTypes = getKeyStorePropValues("keyStoreType",
                    defaultKeyStoreType, storeNames.length);
            String[] storeProviders = getKeyStorePropValues("keyStoreProvider",
                    defaultKeyStoreProvider, storeNames.length);
            String[] storePasswords = getKeyStorePropValues("keyStorePasswd",
                    defaultKeyStorePasswd, storeNames.length);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                SSLLogger.fine("storeNames is : " + Arrays.toString(storeNames));
                SSLLogger.fine("storeTypes is : " + Arrays.toString(storeTypes));
                SSLLogger.fine("storeProviders is : " + Arrays.toString(storeProviders));
            }
            return createInstances(storeNames, storeTypes,
                    storeProviders, storePasswords);
        }

        private static List<KeyStoreDescriptor> createInstances(String[] storeNames, String[] storeTypes,
                                                                String[] storeProviders, String[] storePasswords) {
            List<KeyStoreDescriptor> descriptors = new ArrayList<>();
            int storeCount = storeNames.length;
            if (storeCount == 0) {
                String storeName = "";
                String storeType = storeTypes.length > 0 ? storeTypes[0] : "";
                String storeProvider = storeProviders.length > 0 ? storeProviders[0] : "";
                String storePassword = storePasswords.length > 0 ? storePasswords[0] : "";
                KeyStoreDescriptor descriptor = new KeyStoreDescriptor(storeName, storeType,
                        storeProvider, storePassword);
                descriptors.add(descriptor);
                return descriptors;
            }

            for (int i = 0; i < storeCount; i++) {
                KeyStoreDescriptor descriptor = new KeyStoreDescriptor(storeNames[i], storeTypes[i],
                        storeProviders[i], storePasswords[i]);
                descriptors.add(descriptor);
            }
            return descriptors;
        }
    }

    public static KeyManager[] getKeyManagers() throws Exception {
        List<KeyStoreDescriptor> srcDescriptors = KeyStoreDescriptor.createInstances();
        KeyStoreDescriptor destDescriptor = srcDescriptors.get(0);
        KeyStore destKeyStore = createDestKeyStore(srcDescriptors, destDescriptor);
        /*
         * Try to initialize key manager.
         */
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
            SSLLogger.fine("init keymanager of type " +
                    KeyManagerFactory.getDefaultAlgorithm());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());

        if (P11KEYSTORE.equals(destDescriptor.storeType)) {
            kmf.init(destKeyStore, null); // do not pass key passwd if using token
        } else {
            char[] passwd = destDescriptor.storePassword.isEmpty() ? null :
                    destDescriptor.storePassword.toCharArray();
            kmf.init(destKeyStore, passwd);
        }

        return kmf.getKeyManagers();
    }

    private static KeyStore createDestKeyStore(List<KeyStoreDescriptor> srcDescriptors,
                                               KeyStoreDescriptor destDescriptor) throws Exception {
        int storeCount = srcDescriptors.size();
        String destStoreType = destDescriptor.storeType;
        String destStoreProvider = destDescriptor.storeProvider;
        String destStorePasswd = destDescriptor.storePassword;
        /*
         * If keyStoreCount less than 1 ,load keystore directly.
         * Otherwise, copy the all source keystore to dest keystore.
         */
        KeyStore destKeyStore = null;
        if (storeCount <= 1) {
            destKeyStore = loadKeyStore(destDescriptor);
        } else {
            // Create keystore instance.
            if (!destStoreType.isEmpty()) {
                if (!destStoreProvider.isEmpty()) {
                    destKeyStore = KeyStore.getInstance(destStoreType, destStoreProvider);
                } else {
                    destKeyStore = KeyStore.getInstance(destStoreType);
                }
            }

            if (destKeyStore != null) {
                char[] passwd = destStorePasswd.isEmpty() ? null : destStorePasswd.toCharArray();
                // Load dest keystore
                destKeyStore.load(null, passwd);

                // Copy all src keystore to dest keystore
                for (int i = 0; i < storeCount; i++) {
                    KeyStoreDescriptor srcDescriptor = srcDescriptors.get(i);
                    KeyStore srcKeyStore = loadKeyStore(srcDescriptor);
                    GMTlsUtil.copyKeyStore(srcKeyStore, srcDescriptor.storePassword.toCharArray(),
                            destKeyStore, passwd);
                }
            }
        }
        return destKeyStore;
    }

    private static String[] getKeyStorePropValues(String propKey, String propValue, int storeCount) {
        String[] propValues = new String[0];
        if (!propValue.isEmpty()) {
            propValues = propValue.split(",");
        }

        if (propValues.length > 1 && propValues.length != storeCount) {
            String message = "The keyStore count is " + storeCount + " , " +
                    "the " + propKey + " property value count should be 0 or 1 or equals keyStore count.";
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                SSLLogger.fine(message);
            }
            throw new IllegalArgumentException(message);
        }

        // If keyStoreCount is 0 or propValues length equals keyStoreCount , return propValues.
        if (storeCount == 0 || propValues.length == storeCount) {
            return propValues;
        }

        String[] newPropValues = new String[storeCount];
        String tempPropValue = propValues.length == 0 ? "" : propValues[0];
        Arrays.fill(newPropValues, tempPropValue);
        return newPropValues;
    }

    private static KeyStore loadKeyStore(KeyStoreDescriptor descriptor) throws Exception {
        String storeName = descriptor.storeName;
        String storeType = descriptor.storeType;
        String storePassword = descriptor.storePassword;
        String storeProvider = descriptor.storeProvider;
        if (P11KEYSTORE.equals(storeType) &&
                !NONE.equals(storeName)) {
            throw new IllegalArgumentException("if keyStoreType is "
                    + P11KEYSTORE + ", then keyStore must be " + NONE);
        }

        FileInputStream fs = null;
        KeyStore ks = null;
        char[] passwd = null;
        try {
            if (!storeName.isEmpty() &&
                    !NONE.equals(storeName)) {
                fs = AccessController.doPrivileged(
                        new PrivilegedExceptionAction<FileInputStream>() {
                            @Override
                            public FileInputStream run() throws Exception {
                                return new FileInputStream(storeName);
                            }
                        });
            }

            if (!storePassword.isEmpty()) {
                passwd = storePassword.toCharArray();
            }

            /**
             * Try to initialize key store.
             */
            if ((storeType.length()) != 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,defaultctx")) {
                    SSLLogger.finest("init keystore");
                }
                if (storeProvider.isEmpty()) {
                    ks = KeyStore.getInstance(storeType);
                } else {
                    ks = KeyStore.getInstance(storeType,
                            storeProvider);
                }

                // if defaultKeyStore is NONE, fs will be null
                ks.load(fs, passwd);
            }
        } finally {
            if (fs != null) {
                fs.close();
                fs = null;
            }
        }

        return ks;
    }
}