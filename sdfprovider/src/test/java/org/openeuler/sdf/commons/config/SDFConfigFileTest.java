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

public class SDFConfigFileTest {
    @Test
    public void testConfigFile() {
        System.setProperty("test.sdf.library.dir", "/home/user/lib");
        System.setProperty("test.sdf.logPath.dir", "/home/user/log");
        String configPath = SDFTestUtil.getResource("sdf.conf");
        System.setProperty("sdf.config", configPath);
        SDFConfig sdfConfig = SDFConfig.getInstance();

        // test sdf.enableNonSM
        boolean expectedEnableNonSM = true;
        Assert.assertEquals(expectedEnableNonSM, sdfConfig.isEnableNonSM());

        // test sdf.library
        String expectedLibrary = System.getProperty("test.sdf.library.dir") + "/libtest.so";
        Assert.assertEquals(expectedLibrary, sdfConfig.getLibrary());

        // test sdf.useEncDEK
        boolean expectedUseEncDEK = false;
        Assert.assertEquals(expectedUseEncDEK, sdfConfig.isUseEncDEK());
        System.getProperties().remove("test.sdf.library.dir");

        // test sdf.defaultKEKId
        String expectedDefaultKEKId = "default-kekid";
        Assert.assertEquals(expectedDefaultKEKId, sdfConfig.getDefaultKEKId());

        // test sdf.logPath
        String expectedLogPath = System.getProperty("test.sdf.logPath.dir") + "/sdf.log";
        Assert.assertEquals(expectedLogPath, sdfConfig.getLogPath());

        // test sdf.logLevel
        SDFLogLevel expectedLogLevel = SDFLogLevel.DEBUG;
        Assert.assertEquals(expectedLogLevel, sdfConfig.getLogLevel());

        // test sdf.cleaner.shortInterval
        Assert.assertEquals(1000L, sdfConfig.getShortInterval());

        // test sdf.cleaner.longInterval
        Assert.assertEquals(30000L, sdfConfig.getLongInterval());
    }
}
