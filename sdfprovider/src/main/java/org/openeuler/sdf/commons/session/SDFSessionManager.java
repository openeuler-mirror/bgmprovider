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

package org.openeuler.sdf.commons.session;

import org.openeuler.sdf.commons.config.SDFConfig;
import org.openeuler.sdf.commons.device.SDFDevice;
import org.openeuler.sdf.commons.device.SDFDeviceManager;
import org.openeuler.sdf.wrapper.SDFSessionNative;

/**
 * SDF session manager
 */
public class SDFSessionManager {

    // pool of available sessions
    private final SDFSessionPool sessionPool;

    private final SDFDevice device;

    // instance of SDFSessionManager
    private static final SDFSessionManager instance = new SDFSessionManager();

    private SDFSessionManager() {
        sessionPool = new SDFSessionPool(SDFConfig.getInstance().getSessionCapacity());
        device = SDFDeviceManager.getInstance().getDevice();
    }

    // open new session
    public SDFSession openSession() {
        // open and create session
        long address = SDFSessionNative.nativeOpenSession(device.getAddress());
        return new SDFSession(address);
    }

    // close session
    public SDFSession closeSession(SDFSession session) {
        if (session == null) {
            return null;
        }
        session.close();
        return session;
    }

    // get session
    public SDFSession getSession() {
        // get session from pool
        SDFSession session = sessionPool.poll();
        if (session != null) {
            return session;
        }
        // create new session
        session = openSession();
        return session;
    }

    // release session
    public SDFSession releaseSession(SDFSession session) {
        if (session == null) {
            return null;
        }

        synchronized (session.getReleaseLock()) {
            // The session is already in the pool and will not be processed.
            if (sessionPool.contains(session)) {
                return null;
            }

            // add session to pool
            if (!sessionPool.offer(session)) {
                // close the session directly when the pool is full
                session.close();
            }
        }

        return session;
    }

    public static SDFSessionManager getInstance() {
        return instance;
    }

    public void closeAllSession() {
        SDFSession session;
        while ((session = sessionPool.poll()) != null) {
            session.close();
        }
    }
}
