package org.openeuler.sdf.commons.session;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.sdf.provider.SDFProvider;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public class SDFSessionManagerTest {
    private static final int SESSION_CAPACITY = 10;

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("sdf.session.pool.capacity", SESSION_CAPACITY + "");
        new SDFProvider();
    }

    @Test
    public void testSessionReuse() {
        SDFSessionManager sessionManager = SDFSessionManager.getInstance();
        sessionManager.closeAllSession();

        // open a session and free
        SDFSession sessionFirst = sessionManager.getSession();
        sessionManager.releaseSession(sessionFirst);

        // open a session again
        SDFSession sessionSecond = sessionManager.getSession();
        Assert.assertEquals(sessionFirst, sessionSecond);
    }

    @Test
    public void testSessionCapacity() {
        SDFSessionManager sessionManager = SDFSessionManager.getInstance();
        sessionManager.closeAllSession();

        // init session pool
        SDFSession[] sessions = new SDFSession[SESSION_CAPACITY];
        for (int i = 0; i < sessions.length; i++) {
            sessions[i] = sessionManager.openSession();
            sessionManager.releaseSession(sessions[i]);
        }

        // test that when the pool is full, close the session directly
        SDFSession notPoolSession = sessionManager.openSession();
        notPoolSession = sessionManager.releaseSession(notPoolSession);
        Assert.assertEquals(0L, notPoolSession.getAddress());

        // test that when the pool is not empty, get session from pool
        for (SDFSession session : sessions) {
            SDFSession poolSession = sessionManager.getSession();
            Assert.assertEquals(session, poolSession);
        }

        // test that when the pool is empty, create a new session
        notPoolSession = sessionManager.getSession();
        for (SDFSession session : sessions) {
            Assert.assertNotEquals(session, notPoolSession);
        }
    }

    @Test
    public void testReleaseSessionRepeatedly() throws Exception {
        SDFSessionManager sessionManager = SDFSessionManager.getInstance();
        sessionManager.closeAllSession();

        SDFSession session = sessionManager.getSession();
        int nThreads = 10;
        AtomicInteger num = new AtomicInteger(0);
        ExecutorService executorService = Executors.newFixedThreadPool(nThreads);
        Future<?>[] futures = new Future<?>[nThreads];

        for (int i = 0; i < nThreads; i++) {
            futures[i] = executorService.submit(new Callable<SDFSession>() {
                @Override
                public SDFSession call() {
                    return sessionManager.releaseSession(session);
                }
            });
        }

        try {
            for (Future<?> future : futures) {
                Object sdfSession = future.get();
                if (sdfSession != null) {
                    num.incrementAndGet();
                }
            }
        } finally {
            executorService.shutdown();
        }
        Assert.assertEquals(1, num.get());
    }
}
