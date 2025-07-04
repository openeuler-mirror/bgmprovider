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

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.sdf.commons.log.SDFLogLevel;
import org.openeuler.sdf.commons.util.SDFTestUtil;

import java.util.Random;

public class SDFConfigMixTest {
    private static final int COUNT = 8;
    @Test
    public void testSystemPropertiesAndConfigFile() {
        // random test
        Random random = new Random();
        boolean[] flags = new boolean[COUNT];
        for (int i = 0; i < flags.length; i++) {
            flags[i] = random.nextInt(2) == 1;
        }
        test(flags);
    }

    private void test(boolean[] flags) {
        boolean expectedEnableNonSM = false;
        String expectedLibrary = "/home/user/lib/libtest.so";
        boolean expectedUseEncKEK = true;
        String expectedDefaultKEKId = "default-kekid-new";
        String expectedLogPath = "/home/user/log/sdf.log";
        SDFLogLevel expectedLogLevel = SDFLogLevel.INFO;
        long expectedShortInterval = 5000L;
        long expectedLongInterval = 50000L;
        int idx = 0;
        if (flags[idx++]) {
            System.setProperty("sdf.enableNonSM", String.valueOf(expectedEnableNonSM));
        }
        if (flags[idx++]) {
            System.setProperty("sdf.library", expectedLibrary);
        }
        if (flags[idx++]) {
            System.setProperty("sdf.useEncDEK", String.valueOf(expectedUseEncKEK));
        }
        if (flags[idx++]) {
            System.setProperty("sdf.defaultKEKId", expectedDefaultKEKId);
        }
        if (flags[idx++]) {
            System.setProperty("sdf.logPath", expectedLogPath);
        }
        if (flags[idx++]) {
            System.setProperty("sdf.logLevel", expectedLogLevel.name());
        }
        if (flags[idx++]) {
            System.setProperty("sdf.cleaner.shortInterval", String.valueOf(expectedShortInterval));
        }
        if (flags[idx]) {
            System.setProperty("sdf.cleaner.longInterval", String.valueOf(expectedLongInterval));
        }

        System.setProperty("test.sdf.library.dir", System.getProperty("user.dir"));
        System.setProperty("test.sdf.logPath.dir", System.getProperty("user.dir"));
        String configPath = SDFTestUtil.getResource("sdf.conf");
        System.setProperty("sdf.config", configPath);
        SDFConfig sdfConfig = SDFConfig.getInstance();

        idx = 0;
        expectedEnableNonSM = flags[idx++] ? expectedEnableNonSM : true;
        Assert.assertEquals(expectedEnableNonSM, sdfConfig.isEnableNonSM());

        expectedLibrary = flags[idx++] ? expectedLibrary : System.getProperty("user.dir") + "/libtest.so";
        Assert.assertEquals(expectedLibrary, sdfConfig.getLibrary());

        expectedUseEncKEK = flags[idx++] ? expectedUseEncKEK : false;
        Assert.assertEquals(expectedUseEncKEK, sdfConfig.isUseEncDEK());

        expectedDefaultKEKId = flags[idx++] ? expectedDefaultKEKId : "default-kekid";
        Assert.assertEquals(expectedDefaultKEKId, sdfConfig.getDefaultKEKId());

        expectedLogPath = flags[idx++] ? expectedLogPath : System.getProperty("user.dir") +"/sdf.log";
        Assert.assertEquals(expectedLogPath, sdfConfig.getLogPath());

        expectedLogLevel = flags[idx++] ? expectedLogLevel : SDFLogLevel.DEBUG;
        Assert.assertEquals(expectedLogLevel, sdfConfig.getLogLevel());

        expectedShortInterval = flags[idx++] ? expectedShortInterval : 1000L;
        Assert.assertEquals(expectedShortInterval, sdfConfig.getShortInterval());

        expectedLongInterval = flags[idx] ? expectedLongInterval : 30000L;
        Assert.assertEquals(expectedLongInterval, sdfConfig.getLongInterval());

        System.getProperties().remove("sdf.library");
        System.getProperties().remove("sdf.useEncDEK");
        System.getProperties().remove("sdf.defaultKEKId");
        System.getProperties().remove("test.sdf.library.dir");
        System.getProperties().remove("sdf.logPath");
        System.getProperties().remove("sdf.logLevel");
    }
}
