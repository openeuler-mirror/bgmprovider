/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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
package org.openeuler.tomcat;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

class PEMFile {
    private static final Log log = LogFactory.getLog(PEMFile.class);
    private static final String PEMFILE_CLASSNAME = "org.apache.tomcat.util.net.jsse.PEMFile";

    // org.apache.tomcat.util.net.jsse.PEMFile#PEMFile(String.class,String.class) constructor
    private static Constructor<?> constructor;

    // org.apache.tomcat.util.net.jsse.PEMFile#getCertificates method
    private static Method getCertificatesMethod;

    // org.apache.tomcat.util.net.jsse.PEMFile#getPrivateKey method
    private static Method getPrivateKeyMethod;

    // org.apache.tomcat.util.net.jsse.PEMFile instance
    private final Object pemFile;

    static {
        init();
    }

    public static void init() {
        Class<?> clazz;
        try {
            clazz = Class.forName(PEMFILE_CLASSNAME);
        } catch (ClassNotFoundException e) {
            log.error(String.format("Load class %s failed.", PEMFILE_CLASSNAME));
            throw new InternalError(e);
        }
        constructor = getConstructor(clazz);
        getCertificatesMethod = getCertificatesMethod(clazz);
        getPrivateKeyMethod = getPrivateMethod(clazz);
    }

    private static Constructor<?> getConstructor(Class<?> clazz) {
        Constructor<?> constructor;
        try {
            constructor = clazz.getConstructor(String.class, String.class);
            constructor.setAccessible(true);
        } catch (NoSuchMethodException e) {
            log.warn(String.format(" %s class does not define Constructor(String.class, String.class).",
                    clazz.getSimpleName()));
            throw new InternalError(e);
        }
        return constructor;
    }

    private static Method getCertificatesMethod(Class<?> clazz) {
        Method method;
        try {
            method = clazz.getDeclaredMethod("getCertificates");
            method.setAccessible(true);
        } catch (NoSuchMethodException e) {
            log.warn(String.format(" %s class does not define getCertificates method.", clazz.getName()));
            throw new InternalError(e);
        }
        return method;
    }

    private static Method getPrivateMethod(Class<?> clazz) {
        Method method;
        try {
            method = clazz.getDeclaredMethod("getPrivateKey");
            method.setAccessible(true);
        } catch (NoSuchMethodException e) {
            log.warn(String.format(" %s class does not define getCertificates method.", clazz.getName()));
            throw new InternalError(e);
        }
        return method;
    }

    public PEMFile(String filename) throws IOException {
        this(filename, null);
    }

    public PEMFile(String filename, String password) throws IOException {
        try {
            this.pemFile = constructor.newInstance(filename, password);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new IOException("Failed to create PEMFile instance.", e);
        }
    }

    @SuppressWarnings("unchecked")
    public List<X509Certificate> getCertificates() {
        List<X509Certificate> certificates;
        try {
            certificates = (List<X509Certificate>) getCertificatesMethod.invoke(this.pemFile);
        } catch (IllegalAccessException | InvocationTargetException e) {
            log.error("Invoke getCertificates method failed.", e);
            return new ArrayList<>();
        }
        return certificates;
    }

    public PrivateKey getPrivateKey() {
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) getPrivateKeyMethod.invoke(this.pemFile);
        } catch (IllegalAccessException | InvocationTargetException e) {
            log.error("Invoke getPrivateKey method failed.", e);
        }
        return privateKey;
    }
}
