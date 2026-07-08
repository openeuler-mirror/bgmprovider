/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */
package org.openeuler.sun.misc;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import static org.junit.Assert.*;

public class HexDumpEncoderTest {

    @Test
    public void encodeByteBufferReturnsDumpAndAdvancesPosition() {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[]{0x41, 0x42});
        String encoded = new HexDumpEncoder().encode(buffer);
        assertTrue(encoded.contains("41 42"));
        assertEquals(buffer.limit(), buffer.position());

        ByteBuffer direct = ByteBuffer.allocateDirect(2);
        direct.put(new byte[]{0x43, 0x44});
        direct.flip();
        assertTrue(new HexDumpEncoder().encode(direct).contains("43 44"));
        assertEquals(direct.limit(), direct.position());
    }

    @Test
    public void encodeHandlesFullAndPartialLines() throws Exception {
        byte[] bytes = new byte[20];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i + 0x20);
        }

        HexDumpEncoder encoder = new HexDumpEncoder();
        String encoded = encoder.encode(bytes);
        assertTrue(encoded.startsWith("0000: 20 21 22 23 24 25 26 27"));
        assertTrue(encoded.contains("2F"));
        assertFalse(encoded.endsWith("\n"));

        String bufferEncoded = encoder.encodeBuffer(bytes);
        assertTrue(bufferEncoded.contains("0010: 30 31 32 33"));
        assertTrue(bufferEncoded.endsWith(System.lineSeparator()));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encoder.encodeBuffer(new ByteArrayInputStream(bytes), out);
        assertEquals(bufferEncoded, out.toString());
    }

    @Test
    public void encodeByteBufferAdvancesPositionForBackedAndSlicedBuffers() throws Exception {
        HexDumpEncoder encoder = new HexDumpEncoder();
        ByteBuffer full = ByteBuffer.wrap(new byte[]{0x41, 0x42});
        ByteArrayOutputStream fullOut = new ByteArrayOutputStream();
        encoder.encodeBuffer(full, fullOut);
        assertTrue(fullOut.toString().contains("AB"));
        assertEquals(full.limit(), full.position());

        ByteBuffer partial = ByteBuffer.wrap(new byte[]{0x40, 0x41, 0x42, 0x43});
        partial.position(1);
        partial.limit(3);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encoder.encodeBuffer(partial, out);
        assertTrue(out.toString().contains("41 42"));
        assertEquals(partial.limit(), partial.position());
    }

    @Test
    public void nonPrintableBytesAreRenderedAsDots() {
        String encoded = new HexDumpEncoder().encodeBuffer(new byte[]{0x00, 0x1f, 0x20, 0x7a, 0x7b});
        assertTrue(encoded.endsWith(".. z." + System.lineSeparator()));
    }

    @Test
    public void emptyInputAndHighHexDigitsCoverEncoderBranches() throws Exception {
        HexDumpEncoder encoder = new HexDumpEncoder();
        assertEquals("", encoder.encode(new byte[0]));
        assertEquals("", encoder.encodeBuffer(new byte[0]));
        assertTrue(encoder.encodeBuffer(new byte[]{(byte) 0xab}).contains("AB"));

        ByteBuffer partialArray = ByteBuffer.wrap(new byte[]{0x01, 0x02, 0x03});
        partialArray.position(1);
        assertTrue(encoder.encode(partialArray).contains("02 03"));

        ByteBuffer slicedArray = ByteBuffer.wrap(new byte[]{0x01, 0x02, 0x03, 0x04});
        slicedArray.position(1);
        slicedArray.limit(3);
        assertTrue(encoder.encode(slicedArray.slice()).contains("02 03"));
    }

    @Test
    public void multiByteAtomsCoverPartialAtomBranches() throws Exception {
        PairHexDumpEncoder encoder = new PairHexDumpEncoder();
        ByteArrayOutputStream encodeOut = new ByteArrayOutputStream();
        encoder.encode(new ByteArrayInputStream(new byte[]{0x01, 0x02, 0x03}), encodeOut);
        assertEquals("0102|03|", encodeOut.toString("ISO-8859-1"));

        ByteArrayOutputStream encodeBufferOut = new ByteArrayOutputStream();
        encoder.encodeBuffer(new ByteArrayInputStream(new byte[]{0x04, 0x05, 0x06}), encodeBufferOut);
        assertEquals("0405|06|", encodeBufferOut.toString("ISO-8859-1"));
    }

    private static class PairHexDumpEncoder extends HexDumpEncoder {
        @Override
        protected int bytesPerAtom() {
            return 2;
        }

        @Override
        protected int bytesPerLine() {
            return 3;
        }

        @Override
        protected void encodeLinePrefix(java.io.OutputStream o, int len) {
        }

        @Override
        protected void encodeAtom(java.io.OutputStream o, byte[] buf, int off, int len) throws IOException {
            for (int i = 0; i < len; i++) {
                hexDigit(new java.io.PrintStream(o), buf[off + i]);
            }
            o.write('|');
        }

        @Override
        protected void encodeLineSuffix(java.io.OutputStream o) {
        }
    }
}
