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

import org.apache.catalina.util.ServerInfo;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class TestUtils {
    private static final int JRE_VERSION_8 = 8;
    private static final int JRE_VERSION_11 = 11;

    private static final boolean supportTLS13;
    private static final boolean supportPEMFile;
    private static final TomcatVersion tomcatVersion;
    private static final int jreVersion;
    private static final boolean supportTLS;

    static {
        tomcatVersion = TomcatVersion.valueOf(ServerInfo.getServerInfo());
        supportTLS13 = tomcatVersion.isSupportTLS13();
        supportPEMFile = tomcatVersion.isSupportPEMFile();
        jreVersion = getMajorVersion(System.getProperty("java.specification.version", "1.6"));
        supportTLS = tomcatVersion.isSupportTLS();
    }

    public static String getPath(String fileName) {
        URL url = TestUtils.class.getClassLoader().getResource(fileName);
        if (url != null) {
            try {
                return new URI(url.getPath()).getPath();
            } catch (URISyntaxException e) {
                return null;
            }
        }
        return null;
    }

    public static String getPaths(String[] fileNames) {
        StringBuilder paths = new StringBuilder();
        for (String fileName : fileNames) {
            String path = getPath(fileName);
            if (path != null) {
                paths.append(",").append(path);
            }
        }
        return paths.length() > 0 ? paths.substring(1) : null;
    }

    public static boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }

    public static boolean isEmpty(String[] array) {
        return array == null || array.length == 0;
    }

    public static String arrayToString(String[] array) {
        if (isEmpty(array)) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (String item : array) {
            builder.append(",")
                    .append(item);
        }
        return builder.substring(1);
    }

    // delete directory
    public static boolean deleteDir(File dir) {
        String[] files = dir.list();
        if (files == null) {
            files = new String[0];
        }
        for (String s : files) {
            File file = new File(dir, s);
            if (file.isDirectory()) {
                deleteDir(file);
            } else {
                file.delete();
            }
        }

        boolean isDeleted;
        if (dir.exists()) {
            isDeleted = dir.delete();
        } else {
            isDeleted = true;
        }
        return isDeleted;
    }

    // delete file or directory
    public static boolean delete(File dir) {
        boolean isDeleted;
        if (dir.isDirectory()) {
            isDeleted = deleteDir(dir);
        } else {
            if (dir.exists()) {
                isDeleted = dir.delete();
            } else {
                isDeleted = true;
            }
        }
        return isDeleted;
    }

    public static boolean isSupportTLS13() {
        return supportTLS13;
    }

    public static boolean isSupportPEMFile() {
        return supportPEMFile;
    }

    public static TomcatVersion getTomcatVersion() {
        return tomcatVersion;
    }

    public static boolean isJre8() {
        return jreVersion == JRE_VERSION_8;
    }

    public static boolean isJre11() {
        return jreVersion == JRE_VERSION_11;
    }

    public static int getJreVersion() {
        return jreVersion;
    }

    private static int getMajorVersion(final String javaSpecVersion) {
        final String[] components = javaSpecVersion.split("\\.");
        final int[] version = new int[components.length];
        for (int i = 0; i < components.length; i++) {
            version[i] = Integer.parseInt(components[i]);
        }

        if (version[0] == 1) {
            assert version[1] >= 6;
            return version[1];
        } else {
            return version[0];
        }
    }

    public static boolean isSupportTLS() {
        return supportTLS;
    }
}
