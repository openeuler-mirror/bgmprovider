/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.provider;

import org.openeuler.provider.AbstractEntries;
import org.openeuler.provider.AbstractProvider;
import org.openeuler.sdf.commons.base.SDFNativeResourceCleaner;
import org.openeuler.sdf.commons.config.SDFConfig;
import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.log.SDFLog;
import org.openeuler.sdf.commons.sdk.SDFSDKManager;
import sun.security.util.Debug;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Random;

import static org.openeuler.adaptor.ObjectIdentifierHandler.newObjectIdentifier;

public class SDFProvider extends AbstractProvider {
    private static final long serialVersionUID = 3653325815535521461L;

    private static final Debug debug = Debug.getInstance("provider");

    private static final String NAME = "SDFProvider";
    private static final double VERSION = 1.8d;
    private static final String INFO = "Supports cipher card hardware encryption and decryption";

    private static final String LIB_PATH = "/META-INF/native/";
    private static final String LIB_PREFIX = "lib";
    private static final String LIB_NAME = "sdfcrypto";
    private static final String LIB_SUFFIX = ".so";

    private static final String CDM_SDK_CONFIG = "CDM_SDK_CONFIG";

    private static final String CLEANER_THREAD_NAME = "sdf-cleaner-thread";
    private static final SDFConfig config = SDFConfig.getInstance();


    static {
        initialize();
    }

    public SDFProvider() {
        super(NAME, VERSION, INFO);
    }

    private static void initialize() {
        // load library
        loadLibrary();
        // init log
        initLog();
        // init SDK
        initSDK();
        // init cleaner thread
        initCleanerThread();
        // init NameTable
        initNameTable();
    }

    @SuppressWarnings("unchecked")
    private static void initNameTable() {
        try {
            Field nameTableFiled = AlgorithmId.class.getDeclaredField("nameTable");
            nameTableFiled.setAccessible(true);
            Object object = nameTableFiled.get(null);
            if (!(object instanceof Map)) {
                return;
            }
            Map<ObjectIdentifier, String> nameTable = (Map<ObjectIdentifier, String>) object;
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.104"), "SM4");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.301"), "SM2");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.401"), "SM3");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.501"), "SM3withSM2");
        } catch (Throwable e) {
            // skip
            if (debug != null) {
                debug.println(e.getMessage());
            }
        }
    }

    private static String getLibName() {
        String os = SDFPlatformDependent.normalizedOs();
        String arch = SDFPlatformDependent.normalizedArch();
        return LIB_PREFIX + LIB_NAME + "_" + os + "_" + arch;
    }

    private static String getLibrary() {
        String libName = getLibName();
        return LIB_PATH + libName + LIB_SUFFIX;
    }

    // load libsdfcrypto.so
    private static void loadLibrary() {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    // create temporary directory. default directory "/tmp"
                    String tmpPath = System.getProperty("java.io.tmpdir") + "/";
                    File tmpDic = new File(tmpPath);
                    if (!tmpDic.exists()) {
                        throw new IOException("create temporary directory failed");
                    }
                    String tmpLibName = getTmpLibName();
                    File tmpLibFile = new File(tmpPath + tmpLibName);
                    if (!tmpLibFile.exists()) {
                        if(!tmpLibFile.createNewFile()) {
                            throw new IOException("create temporary lib file failed");
                        }
                    }
                    // copy libsdfcrypto.so to tmpLibFile
                    String library = getLibrary();
                    if (debug != null) {
                        debug.println("library=" + library);
                    }
                    InputStream cryptoInputStream = getClass().getResourceAsStream(library);
                    if (cryptoInputStream == null) {
                        throw new FileNotFoundException(library);
                    }
                    File absoluteFile = tmpLibFile.getAbsoluteFile();
                    Files.copy(cryptoInputStream,
                            absoluteFile.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);

                    // set the owner's execute permission
                    boolean canExecute = tmpLibFile.setExecutable(true);
                    if (!canExecute) {
                        throw new IOException(tmpLibFile.getName() + "setExecutable failed");
                    }
                    System.load(absoluteFile.getAbsolutePath());

                } catch (Throwable e) {
                    // skip
                    if (debug != null) {
                        debug.println(e.getMessage());
                    }
                }
                return null;
            }
        });
    }

    /**
     * Get tmp lib name
     */
    private static String getTmpLibName() {
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        int processID = Integer.parseInt(runtimeMXBean.getName().split("@")[0]);
        Random tmpRandom = new Random();
        String version = SDFProvider.class.getPackage().getImplementationVersion();
        return getLibName() + "-" + version + "-" + processID + tmpRandom.nextLong() + LIB_SUFFIX;
    }

    /**
     * Init log
     */
    private static void initLog() {
        if (config.getLogPath() != null) {
            SDFLog.init(config.getLogPath(), config.getLogLevel());
        }
    }

    /**
     * Init SDK, supports the following two configuration methods:
     * 1. using the sdf.sdkConfig system property: -Dsdf.sdkConfig=/path/sdk.config
     * 2. using the environment variable CDM_SDK_CONFIG  export CDM_SDK_CONFIG=/path/sdk.config
     */
    private static void initSDK() {
        String sdkConfig = config.getSdkConfig();

        if (sdkConfig == null && System.getenv(CDM_SDK_CONFIG) == null) {
            if (debug != null) {
                debug.println("Missing SDK config file");
            }
            return;
        }

        if (debug != null) {
            debug.println("SDK config file :" + sdkConfig);
        }
        try {
            SDFSDKManager.init(sdkConfig);
        } catch (SDFException e) {
            if (debug != null) {
                debug.println(e.getMessage());
            }
        }
    }

    /**
     * Init cleaner thread
     */
    private static void initCleanerThread() {
        Runnable cleaner = new SDFNativeResourceCleaner(config.getShortInterval(), config.getShortInterval());
        Thread cleanerThread = new Thread(cleaner);
        cleanerThread.setName(CLEANER_THREAD_NAME);
        cleanerThread.setPriority(Thread.MIN_PRIORITY);
        cleanerThread.setDaemon(true);
        cleanerThread.start();
    }

    /**
     * Get static Random Instance
     */
    public static SecureRandom getRandom() {
        return SecureRandomHolder.RANDOM;
    }

    private static class SecureRandomHolder {
        static final SecureRandom RANDOM = new SecureRandom();
    }

    @Override
    protected AbstractEntries createEntries(Provider provider) {
        return new SDFEntries(provider);
    }
}
