package org.openeuler.sdf.commons.session;

import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * SDF session pool
 */
public class SDFSessionPool {
    private final Queue<SDFSession> pool;

    SDFSessionPool(int capacity) {
        if (capacity > 0) {
            this.pool = new LinkedBlockingQueue<>(capacity);
        } else {
            this.pool = null;
        }
    }

    SDFSession poll() {
        if (pool == null) {
            return null;
        }
        return pool.poll();
    }

    boolean offer(SDFSession session) {
        if (pool == null) {
            return false;
        }
        return pool.offer(session);
    }

    boolean contains(SDFSession session) {
        if (pool == null) {
            return false;
        }
        return pool.contains(session);
    }
}
