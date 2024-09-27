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

public class SDFConfigDefaultTest {
    @Test
    public void testDefault() {
        SDFConfig sdfConfig = SDFConfig.getInstance();
        // test sdf.enableNonSM
        boolean expectedEnableNonSM = false;
        Assert.assertEquals(expectedEnableNonSM, sdfConfig.isEnableNonSM());

        // test sdf.library
        Assert.assertNull(sdfConfig.getLibrary());

        // test sdf.useEncDEK
        Assert.assertTrue(sdfConfig.isUseEncDEK());

        // test sdf.defaultKEKId
        Assert.assertEquals("", sdfConfig.getDefaultKEKId());

        // test sdf.logPath
        Assert.assertNull(sdfConfig.getLogPath());

        // test sdf.logLevel
        Assert.assertEquals(SDFLogLevel.OFF, sdfConfig.getLogLevel());

        // test sdf.cleaner.shortInterval
        Assert.assertEquals(2000L, sdfConfig.getShortInterval());

        // test sdf.cleaner.longInterval
        Assert.assertEquals(60000L, sdfConfig.getLongInterval());

        // test sdf.session.pool.capacity
        Assert.assertEquals(1024L, sdfConfig.getSessionCapacity());
    }
}
