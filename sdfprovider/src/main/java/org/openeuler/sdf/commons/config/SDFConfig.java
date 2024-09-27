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

package org.openeuler.sdf.commons.config;

import org.openeuler.sdf.commons.exception.SDFConfigException;
import org.openeuler.sdf.commons.log.SDFLogLevel;
import sun.security.pkcs11.wrapper.PKCS11RuntimeException;
import sun.security.util.Debug;
import sun.security.util.PropertyExpander;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Properties;

/**
 * SDF config
 */
public class SDFConfig {
    private static final Debug sdebug = Debug.getInstance("properties");
    private final String fileName;

    // enable non-SM algorithm (RSA/AES/HmacSHA1/HmacSHA256.../SHA1/SHA256...)
    private boolean enableNonSM;

    // libswsds.so path, support system properties, such as ${user.dir}
    private String library;

    // use encrypted DEK
    private boolean useEncDEK;

    // default KEK id
    private String defaultKEKId;

    // default region id
    private String defaultRegionId;

    // default cdp id
    private String defaultCdpId;

    // default pin
    private String defaultPin;

    // log path
    private String logPath;

    // log level
    private SDFLogLevel logLevel;

    // cleaner short interval
    private long shortInterval;

    // cleaner long longInterval
    private long longInterval;

    // session pool capacity
    private int sessionCapacity;

    private final Properties props = new Properties();

    private static final SDFConfig instance = new SDFConfig();

    private SDFConfig() {
        this.fileName = System.getProperty("sdf.config");
        try {
            if (fileName != null) {
                load(fileName);
            }
            parse();
        } catch (IOException e) {
            // skip
            if (sdebug != null) {
                sdebug.println(e.getMessage());
            }
        }
    }

    public static SDFConfig getInstance() {
        return instance;
    }

    /**
     * load sdf configuration file
     *
     * @param fileName configuration file name
     */
    private void load(String fileName) throws IOException {
        File file = new File(fileName);
        if (!file.exists()) {
            if (sdebug != null) {
                sdebug.println("file does not exist:" + fileName);
            }
            return;
        }

        try {
            file = file.getCanonicalFile();
        } catch (IOException e) {
            if (sdebug != null) {
                sdebug.println("get canonical file failed:" + fileName);
                sdebug.println(e.getMessage());
            }
        }

        try (InputStream inputStream = Files.newInputStream(file.toPath())) {
            props.load(inputStream);
        } catch (IOException e) {
            if (sdebug != null) {
                sdebug.println("unable to load file:" + fileName);
                sdebug.println(e.getMessage());
            }
            throw e;
        }

        if (sdebug != null) {
            sdebug.println("reading file:" + fileName);
        }
    }

    private void parse() throws IOException {
        this.enableNonSM = parseEnableNonSM();
        this.library = parseLibrary();
        this.useEncDEK = parseUseEncKEK();
        this.defaultKEKId = parseDefaultKEKId();
        this.defaultRegionId = parseDefaultRegionId();
        this.defaultCdpId = parseDefaultCdpId();
        this.defaultPin = parseDefaultPin();
        this.logPath = parseLogPath();
        this.logLevel = parseLogLevel();
        this.shortInterval = parseShortInterval();
        this.longInterval = parseLongInterval();
        this.sessionCapacity = parseSessionCapacity();
    }

    private boolean parseEnableNonSM() {
        String enableNonSM = getProperty(SDFConfigConstant.SDF_ENABLE_NON_SM, "false");
        return Boolean.parseBoolean(enableNonSM);
    }

    private String parseLibrary() throws IOException {
        return parseFile(SDFConfigConstant.SDF_LIBRARY);
    }

    private String parseFile(String key) throws IOException {
        String path = getProperty(key);
        if (path == null) {
            return null;
        }
        path = expand(path);
        File file = new File(path);
        if (!file.isAbsolute()) {
            throw new SDFConfigException("Absolute path required for " + key + " value: " + path);
        }

        path = file.getCanonicalPath();
        if (sdebug != null) {
            sdebug.println(key + "canonical path:" + path);
        }
        return path;
    }

    private static String expand(String value) throws SDFConfigException {
        String expandValue;
        try {
            expandValue = PropertyExpander.expand(value);
        } catch (Exception e) {
            throw new SDFConfigException(e);
        }
        if (sdebug != null) {
            sdebug.println(value + "=" + expandValue);
        }
        return expandValue;
    }

    private boolean parseUseEncKEK() {
        String useEncKEK = getProperty(SDFConfigConstant.SDF_USEENCDEK, "true");
        return Boolean.parseBoolean(useEncKEK);
    }

    private String parseDefaultKEKId() {
        return getProperty(SDFConfigConstant.SDF_DEFAULT_KEK_ID, "");
    }

    private String parseDefaultRegionId() {
        return getProperty(SDFConfigConstant.SDF_DEFAULT_REGION_ID, "");
    }

    private String parseDefaultCdpId() {
        return getProperty(SDFConfigConstant.SDF_DEFAULT_CDP_ID, "");
    }

    private String parseDefaultPin() {
        return getProperty(SDFConfigConstant.SDF_DEFAULT_PIN, "");
    }

    private String parseLogPath() throws IOException {
        return parseFile(SDFConfigConstant.SDF_LOG_PATH);
    }

    private SDFLogLevel parseLogLevel() {
        SDFLogLevel defaultLogLevel = this.logPath != null ? SDFLogLevel.INFO : SDFLogLevel.OFF;
        String value = getProperty(SDFConfigConstant.SDF_LOG_LEVEL);
        if (value == null) {
            return defaultLogLevel;
        }

        try {
            return SDFLogLevel.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            if (sdebug != null) {
                sdebug.println(e.getMessage());
            }
            return defaultLogLevel;
        }
    }

    private long parseShortInterval() {
        long shortInterval = getLongProperty(SDFConfigConstant.SDF_CLEANER_SHORT_INTERVAL, 2000);
        if (shortInterval <= 0) {
            throw new PKCS11RuntimeException("Illegal value of" + SDFConfigConstant.SDF_CLEANER_SHORT_INTERVAL);
        }
        return shortInterval;
    }

    private long parseLongInterval() {
        long longInterval = getLongProperty(SDFConfigConstant.SDF_CLEANER_LONG_INTERVAL, 60000);
        if (longInterval <= 0) {
            throw new PKCS11RuntimeException("Illegal value of" + SDFConfigConstant.SDF_CLEANER_LONG_INTERVAL);
        }
        return longInterval;
    }

    private int parseSessionCapacity() {
        return getIntProperty(SDFConfigConstant.SDF_SESSION_CAPACITY, 1024);
    }

    public String getProperty(String key) {
        if (System.getSecurityManager() == null) {
            return getPropertyValue(key);
        }
        return AccessController.doPrivileged(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return getPropertyValue(key);
            }
        });
    }

    private String getPropertyValue(String key) {
        String value = System.getProperty(key);
        if (sdebug != null) {
            sdebug.println("System.getProperty(" + key + ")" + "=" + value);
        }
        if (value == null) {
            value = props.getProperty(key);
            if (sdebug != null) {
                sdebug.println("props.getProperty(" + key + ")" + "=" + value);
            }
        }
        return value;
    }

    public String getProperty(String key, String defaultValue) {
        String value = getProperty(key);
        return value != null ? value : defaultValue;
    }

    private int getIntProperty(String key, int defaultValue) {
        String value = getProperty(key);
        return value != null ? Integer.parseInt(value) : defaultValue;
    }

    private long getLongProperty(String key, long defaultValue) {
        String value = getProperty(key);
        return value != null ? Long.parseLong(value) : defaultValue;
    }

    public String getFileName() {
        return fileName;
    }

    public boolean isEnableNonSM() {
        return enableNonSM;
    }

    public String getLibrary() {
        return library;
    }

    public boolean isUseEncDEK() {
        return useEncDEK;
    }

    public String getDefaultKEKId() {
        return defaultKEKId;
    }

    public String getDefaultRegionId() {
        return defaultRegionId;
    }

    public String getDefaultPin() {
        return defaultPin;
    }

    public String getDefaultCdpId() {
        return defaultCdpId;
    }

    public String getLogPath() {
        return logPath;
    }

    public SDFLogLevel getLogLevel() {
        return logLevel;
    }

    public long getShortInterval() {
        return shortInterval;
    }

    public long getLongInterval() {
        return longInterval;
    }

    public int getSessionCapacity() {
        return sessionCapacity;
    }
}
