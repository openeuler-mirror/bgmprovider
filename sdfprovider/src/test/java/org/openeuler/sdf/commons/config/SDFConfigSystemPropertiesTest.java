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
import org.openeuler.sdf.commons.config.SDFConfig;
import org.openeuler.sdf.commons.log.SDFLogLevel;

public class SDFConfigSystemPropertiesTest {
    @Test
    public void testSystemProperties() {
        String expectedLibrary = "/home/user/lib/libtest.so";
        boolean expectedUseEncKEK = false;
        String expectedDefaultKEKId = "default-kekid-new";
        String expectedLogPath = "/home/user/log/sdf.log";
        SDFLogLevel expectedLogLevel = SDFLogLevel.DEBUG;
        long expectedShortInterval = 5000L;
        long expectedLongInterval = 50000L;
        System.setProperty("sdf.library", expectedLibrary);
        System.setProperty("sdf.useEncDEK", String.valueOf(expectedUseEncKEK));
        System.setProperty("sdf.defaultKEKId", expectedDefaultKEKId);
        System.setProperty("sdf.logPath", expectedLogPath);
        System.setProperty("sdf.logLevel", expectedLogLevel.name());
        System.setProperty("sdf.cleaner.shortInterval", String.valueOf(expectedShortInterval));
        System.setProperty("sdf.cleaner.longInterval", String.valueOf(expectedLongInterval));
        SDFConfig sdfConfig = SDFConfig.getInstance();

        Assert.assertEquals(expectedLibrary, sdfConfig.getLibrary());
        Assert.assertEquals(expectedUseEncKEK, sdfConfig.isUseEncDEK());
        Assert.assertEquals(expectedDefaultKEKId, sdfConfig.getDefaultKEKId());
        Assert.assertEquals(expectedLogPath, sdfConfig.getLogPath());
        Assert.assertEquals(expectedShortInterval, sdfConfig.getShortInterval());
        Assert.assertEquals(expectedLongInterval, sdfConfig.getLongInterval());

        System.getProperties().remove("sdf.library");
        System.getProperties().remove("sdf.useEncDEK");
        System.getProperties().remove("sdf.defaultKEKId");
        System.getProperties().remove("sdf.logPath");
        System.getProperties().remove("sdf.logLevel");
        System.getProperties().remove("sdf.cleaner.shortInterval");
        System.getProperties().remove("sdf.cleaner.longInterval");
    }
}
