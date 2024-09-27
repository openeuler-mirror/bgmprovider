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

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public abstract class AbstractSDFRef<T> extends PhantomReference<T>
        implements Comparable<AbstractSDFRef<T>> {
    private static final ReferenceQueue<Object> refQueue =
            new ReferenceQueue<>();
    private static final Set<AbstractSDFRef<?>> refList =
            Collections.synchronizedSet(new HashSet<>());
    private long address;

    protected AbstractSDFRef(T reference, long address) {
        super(reference, refQueue);
        this.address = address;
        refList.add(this);
    }

    public long getAddress(){
        return address;
    }

    public void dispose() {
        // remove strong reference
        refList.remove(this);

        // free native memory
        try {
            if (address != 0L) {
                free(address);
            }
        } finally {
            address = 0L;
            this.clear();
        }
    }

    /**
     * free native memory
     * @param address handle address
     */
    protected abstract void free(long address);

    @Override
    public int compareTo(AbstractSDFRef other) {
        if (this.address == other.address) {
            return 0;
        } else {
            return (this.address < other.address) ? -1 : 1;
        }
    }

    /**
     * Called by the NativeResourceCleaner at specified intervals
     * @see SDFNativeResourceCleaner
     * @return found
     */
    static boolean drainRefQueue() {
        boolean found = false;
        AbstractSDFRef<?> next;
        while ((next = (AbstractSDFRef<?>) refQueue.poll()) != null) {
            found = true;
            next.dispose();
        }
        return found;
    }

    public static Set<AbstractSDFRef<?>> getRefList() {
        return refList;
    }
}
