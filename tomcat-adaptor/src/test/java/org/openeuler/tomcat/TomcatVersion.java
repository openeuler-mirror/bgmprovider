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

import org.openeuler.JavaVersion;

import java.util.Arrays;

public class TomcatVersion implements Comparable<TomcatVersion> {
    public static final TomcatVersion V8_5_2 = new TomcatVersion("8.5.2");
    public static final TomcatVersion V8_5_24 = new TomcatVersion("8.5.24");
    public static final TomcatVersion V8_5_30 = new TomcatVersion("8.5.30");

    public static final TomcatVersion V9_0_0_M3 = new TomcatVersion("9.0.0.M3");
    public static final TomcatVersion V9_0_0_M5 = new TomcatVersion("9.0.0.M5");
    public static final TomcatVersion V9_0_0_M17 = new TomcatVersion("9.0.0.M17");
    public static final TomcatVersion V9_0_3 = new TomcatVersion("9.0.3");
    public static final TomcatVersion V9_0_7 = new TomcatVersion("9.0.7");

    private static final int VERSION_LENGTH = 4;
    private static final String SPLIT_CHAR = "[-.]";
    private final int[] versions;
    private final String fullVersion;

    public TomcatVersion(String fullVersion) {
        this.fullVersion = fullVersion;
        this.versions = parseFullVersion(fullVersion);
    }

    private int[] parseFullVersion(String fullVersion) {
        String[] versionArray = fullVersion.replace("M", "")
                .split(SPLIT_CHAR);
        if (versionArray.length > VERSION_LENGTH) {
            throw new IllegalArgumentException("Illegal tomcat version.");
        }
        int[] versions = new int[VERSION_LENGTH];
        for (int i = 0; i < versionArray.length; i++) {
            versions[i] = Integer.parseInt(versionArray[i]);
        }
        return versions;
    }

    /*
     * The Tomcat version format is as follows:
     *     Apache Tomcat/x.x.x
     *     Apache Tomcat/x.x.x.Mx
     *     Apache Tomcat/x.x.x-Mx
     */
    public static TomcatVersion valueOf(String versionStr) {
        if (versionStr == null) {
            throw new IllegalArgumentException("");
        }
        String fullVersion = versionStr.replace("Apache Tomcat/", "");
        return new TomcatVersion(fullVersion);
    }

    @Override
    public int compareTo(TomcatVersion that) {
        if (that == null) {
            throw new IllegalArgumentException("");
        }

        for (int i = 0; i < VERSION_LENGTH; i++) {
            if (versions[i] > that.versions[i]) {
                return 1;
            } else if (versions[i] < that.versions[i]) {
                return -1;
            }
        }
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TomcatVersion that = (TomcatVersion) o;
        return Arrays.equals(versions, that.versions);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(versions);
    }

    public boolean isVersion10Plus() {
        return versions[0] >= 10;
    }

    public boolean isVersion9() {
        return versions[0] == 9;
    }

    public boolean isVersion8_5() {
        return versions[0] == 8 && versions[1] == 5;
    }

    /*
     * The following tomcat versions support TLSv1.3 :
     * Tomcat 10.0.x  all
     * Tomcat  9.0.x  9.0.7 and above
     * Tomcat  8.5.x  8.5.30 and above
     */
    public boolean isSupportTLS13() {
        if (!isSupportedVersion()) {
            return false;
        }
        if (compareTo(V9_0_7) >= 0) {
            return true;
        }
        return isVersion8_5() && compareTo(V8_5_30) >= 0;
    }

    /*
     * The following tomcat versions support PEM file :
     * Tomcat 10.0.x  all
     * Tomcat  9.0.x  9.0.0.M5 and above
     * Tomcat  8.5.x  all
     */
    public boolean isSupportPEMFile() {
        if (!isSupportedVersion()) {
            return false;
        }
        if (isVersion8_5() || isVersion10Plus()) {
            return true;
        }
        return isVersion9() && compareTo(V9_0_0_M5) >= 0;
    }

    /*
     * The following versions of tomcat will throw NPE when create SSLEngine,
     * causing TLS to be unavailable in jre 11. For more detail information,
     * please refer to https://bz.apache.org/bugzilla/show_bug.cgi?id=61914
     * Tomcat 9.0.x  9.0.0.M17 < version < 9.0.3
     * Tomcat 8.5.x  8.5.24
     */
    public boolean isSupportTLS() {
        if (!isSupportedVersion()) {
            return false;
        }
        if (JavaVersion.isJava8()) {
            return true;
        } else if (JavaVersion.isJava11PlusSpec()) {
            if (equals(V8_5_24)) {
                return false;
            }
            return compareTo(V9_0_0_M17) <=0 || compareTo(V9_0_3) >= 0;
        } else {
            throw new IllegalStateException("Unsupported jre version : "
                    + JavaVersion.current());
        }
    }

    /*
     * The following tomcat versions are valid :
     * Tomcat 10.0.x  all
     * Tomcat  9.0.x  9.0.0.M3 and above
     * Tomcat  8.5.x  8.5.2 and above
     */
    public boolean isSupportedVersion() {
        if (isVersion8_5() && compareTo(TomcatVersion.V8_5_2) >= 0) {
            return true;
        }
        if (isVersion9() && compareTo(TomcatVersion.V9_0_0_M3) >= 0) {
            return true;
        }
        return isVersion10Plus();
    }

    @Override
    public String toString() {
        return fullVersion;
    }
}
