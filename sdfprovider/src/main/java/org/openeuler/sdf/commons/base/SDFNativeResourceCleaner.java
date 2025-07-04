/*
 * Copyright (c) 2003, 2021, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */


package org.openeuler.sdf.commons.base;

public class SDFNativeResourceCleaner implements Runnable {
    private final long shortInterval;
    private final long longInterval;

    private long sleepMillis;

    private int count = 0;

    public SDFNativeResourceCleaner(long shortInterval, long longInterval) {
        this.shortInterval = shortInterval;
        this.longInterval = longInterval;
        this.sleepMillis = shortInterval;
    }

    /*
     * The cleaner.shortInterval and cleaner.longInterval properties
     * may be defined in the sdf config file and are specified in milliseconds
     * Minimum value is 1000ms.  Default values :
     *  sdf.cleaner.shortInterval : 2000ms
     *  sdf.cleaner.longInterval  : 60000ms
     *
     * The cleaner thread runs at cleaner.shortInterval intervals
     * while references continue to be found for cleaning.
     * If 100 iterations occur with no references being found, then the interval
     * period moves to cleaner.longInterval value. The cleaner thread moves back
     * to short interval checking if a resource is found
     */
    @Override
    public void run() {
        while (true) {
            // sleep
            try {
                Thread.sleep(sleepMillis);
            } catch (InterruptedException ie) {
                break;
            }

            // TODO
            //  Whether to prevent thread exit caused by the free failure?
            boolean found = AbstractSDFRef.drainRefQueue();
            if (!found) {
                count++;
                if (count > 100) {
                    // no reference freed for some time
                    // increase the sleep time
                    sleepMillis = longInterval;
                }
            } else {
                count = 0;
                sleepMillis = shortInterval;
            }
        }
    }
}
