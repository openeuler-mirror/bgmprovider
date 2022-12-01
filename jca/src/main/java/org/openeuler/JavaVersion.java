/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
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

import java.security.AccessController;
import java.security.PrivilegedAction;

public class JavaVersion {
    // 8.0.351
    public static JavaVersion V_8_0_351 = new JavaVersion(8, 351);
    // 11.0.17
    public static JavaVersion V_11_0_17 = new JavaVersion(11, 17);
    // 12.0.19
    public static JavaVersion V_12_0_19 = new JavaVersion(12, 19);
    // 13.0.23
    public static JavaVersion V_13_0_23 = new JavaVersion(13, 23);
    // 17.0.2
    public static JavaVersion V_17_0_2 = new JavaVersion(17, 2);

    private static class JavaVersionHolder {
        private static final JavaVersion CURRENT_VERSION = getCurrentJavaVersion();
        private static final String CURRENT_VENDOR = getCurrentJavaVendor();

        private static JavaVersion getCurrentJavaVersion() {
            String versionStr = AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
                public String run() {
                    return System.getProperty("java.version");
                }
            });
            if (versionStr == null) {
                return new JavaVersion(8, 302);
            }

            // Use 4 bytes to store the version number
            int[] newVersions = new int[4];
            String ch = "_";
            if (versionStr.contains(ch)) { // 1.8.0_x,
                String[] items = versionStr.split(ch);
                int[] versions = getVersions(items[0]);
                // ignore the first version number (1)
                System.arraycopy(versions, 1, newVersions, 0, 2);
                newVersions[2] = Integer.parseInt(items[1]);
            } else { // x.x.x or x.x.x.x
                int[] versions = getVersions(versionStr);
                System.arraycopy(versions, 0, newVersions, 0, versions.length);
            }
            return new JavaVersion(newVersions[0], newVersions[2], newVersions);
        }

        private static int[] getVersions(String versionStr) {
            String[] components = versionStr.split("\\.");
            final int[] version = new int[components.length];
            for (int i = 0; i < components.length; i++) {
                version[i] = Integer.parseInt(components[i]);
            }
            return version;
        }

        private static boolean isOracleJdk() {
            String currentJavaVendor = getCurrentJavaVendor();
            return currentJavaVendor != null && currentJavaVendor.startsWith("Oracle");
        }
    }

    private static String getCurrentJavaVendor() {
        return AccessController.doPrivileged(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return System.getProperty("java.vendor");
            }
        });
    }

    private final int majorVersion;

    private final int minorVersion;

    private final int[] versions;

    private JavaVersion(int majorVersion, int minorVersion, int[] versions) {
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.versions = versions;
    }

    private JavaVersion(int majorVersion, int minorVersion) {
        this(majorVersion, minorVersion, new int[]{majorVersion, 0, minorVersion, 0});
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        if (this.majorVersion <= 8) {
            stringBuilder.append("1");
            for (int i = 0; i < versions.length - 2; i++) {
                stringBuilder.append(".");
                stringBuilder.append(versions[i]);
            }
            stringBuilder.append("_");
            stringBuilder.append(versions[versions.length - 2]);
            return stringBuilder.toString();
        } else {
            for (int i = 0 ; i < versions.length - 1; i++) {
                stringBuilder.append(".");
                stringBuilder.append(versions[i]);
            }
            if (versions[versions.length - 1] != 0) {
                stringBuilder.append(".");
                stringBuilder.append(versions[versions.length - 1]);
            }
            return stringBuilder.substring(1);
        }
    }

    public static boolean isJava17PlusSpec() {
        return current().majorVersion >= 17;
    }

    public static boolean isJava8() {
        return current().majorVersion == 8;
    }

    public static boolean isJava11() {
        return current().majorVersion == 11;
    }

    public static boolean isJava12PlusSpec() {
        return current().majorVersion >= 12;
    }

    public static boolean isJava11PlusSpec() {
        return current().majorVersion >= 11;
    }

    public static boolean isOracleJdk() {
        return JavaVersionHolder.CURRENT_VENDOR != null && JavaVersionHolder.CURRENT_VENDOR.startsWith("Oracle");
    }

    public static JavaVersion current() {
        return JavaVersionHolder.CURRENT_VERSION;
    }

    public int compare(JavaVersion javaVersion) {
        for (int i = 0; i < versions.length; i++) {
            if (this.versions[i] > javaVersion.versions[i]) {
                return 1;
            } else if (this.versions[i] < javaVersion.versions[i]) {
                return -1;
            }
        }
        return 0;
    }
    public static boolean higherThanOrEquals(JavaVersion javaVersion) {
        return current().compare(javaVersion) >= 0;
    }

    public static boolean lowerThanOrEquals(JavaVersion javaVersion) {
        return current().compare(javaVersion) <= 0;
    }

    public static boolean equals(JavaVersion javaVersion) {
        return current().compare(javaVersion) == 0;
    }
}
