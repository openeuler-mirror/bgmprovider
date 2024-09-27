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

package org.openeuler.sdf.commons.base;

import org.junit.Assert;
import org.junit.Test;

import java.util.Set;

public class SDFNativeResourceCleanerTest {
    private static final int HANDLE_COUNT = 10;
    private static final long CLEANER_SHORT_INTERVAL = 20L;
    private static final long CLEANER_LONG_INTERVAL = 20L;
    private static final long SLEEP_TIME_AFTER_GC = 100L;

    @Test
    public void test() throws InterruptedException {
        // create cleaner thread
        createCleaner();

        // before gc
        Set<AbstractSDFRef<?>> refList = AbstractSDFRef.getRefList();
        for (int i = 0; i < HANDLE_COUNT; i++) {
            SDFExampleHandle sdfExampleHandle = new SDFExampleHandle(0L);
        }
        Assert.assertEquals(HANDLE_COUNT, refList.size());

        // after gc
        System.gc();
        Thread.sleep(SLEEP_TIME_AFTER_GC);
        Assert.assertTrue(refList.size() < HANDLE_COUNT);
    }

    private void createCleaner() {
        Runnable cleaner = new SDFNativeResourceCleaner(CLEANER_SHORT_INTERVAL, CLEANER_LONG_INTERVAL);
        Thread cleanerThread = new Thread(
                cleaner);
        cleanerThread.setName("Cleanup-SDF");
        cleanerThread.setPriority(Thread.MIN_PRIORITY);
        cleanerThread.setDaemon(true);
        cleanerThread.start();
    }
}
