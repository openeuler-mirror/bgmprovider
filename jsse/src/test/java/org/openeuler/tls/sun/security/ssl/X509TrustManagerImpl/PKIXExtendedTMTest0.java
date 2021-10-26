/*
 * Copyright (c) 2010, 2016, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

package org.openeuler.tls.sun.security.ssl.X509TrustManagerImpl;

//
// SunJSSE does not support dynamic system properties, no way to re-use
// system properties in samevm/agentvm mode.
//

/*
 * @test
 * @bug 6916074 8170131
 * @summary Add support for TLS 1.2
 * @run main/othervm PKIXExtendedTM 0
 * @run main/othervm PKIXExtendedTM 1
 * @run main/othervm PKIXExtendedTM 2
 * @run main/othervm PKIXExtendedTM 3
 */

import org.junit.Test;

import java.net.*;
import java.util.*;
import java.io.*;
import javax.net.ssl.*;
import java.security.Security;
import java.security.KeyStore;
import java.security.KeyFactory;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPathValidatorException;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;

public class PKIXExtendedTMTest0 {
    @Test
    public void testPKIXExtendedTMTest0() throws Exception {
        PKIXExtendedTM.main(new String[]{"0"});
    }
}
