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

import sun.security.util.Debug;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Properties;

public class Config {
    private static final Debug debug = Debug.getInstance("provider");

    private static final Properties config = new Properties();

    private static boolean useLegacyJCE = false;


    static {
        initConfig();
        useLegacyJCE = Config.enable("jce.useLegacy", "false");
    }

    private Config() {

    }

    private static void initConfig() {
        String path;
        if (System.getSecurityManager() != null) {
            path = System.getProperty("bgmprovider.conf");
        } else {
            path = AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
                public String run() {
                    return System.getProperty("bgmprovider.conf");
                }
            });
        }
        if (debug != null) {
            debug.println("bgmprovider.conf: " + path);
        }
        if (path == null) {
            return;
        }

        File file = new File(path);
        if (!file.exists()) {
            return;
        }

        try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(file.toPath()))) {
            config.load(inputStream);
        } catch (IOException e) {
            if (debug != null) {
                debug.println(e.getMessage());
            }
        }
    }

    /**
     * System properties take precedence over configuration files
     * @param key
     * @return
     */
    static boolean enable(String key) {
        return enable(key, "true");
    }

    static boolean enable(String key, String defaultValue) {
        String value = AccessController.doPrivileged(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return System.getProperty(key);
            }
        });
        if (debug != null) {
            debug.println("System.getProperty(\"" + key + "\")=" + value);
        }
        if (value == null) {
            value = (String) config.getOrDefault(key, defaultValue);
            if (debug != null) {
                debug.println("config.getOrDefault(\"" + key + "\",\"" + defaultValue + "\")=" + value);
            }
        }
        return Boolean.parseBoolean(value);
    }

    public static boolean useLegacyJCE() {
        return useLegacyJCE;
    }
}
