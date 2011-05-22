/*
 * Copyright (C) 2007 Robey Pointer <robey@lag.net>
 *
 * This file is part of jaramiko.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package net.lag.jaramiko.ber;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import junit.framework.TestCase;
import net.lag.jaramiko.Util;

public class BEROutputStreamTest extends TestCase {
    public void testSimple() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(Integer.valueOf(23));
        assertEquals("020117", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(Long.valueOf(23));
        assertEquals("020117", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(BigInteger.valueOf(23));
        assertEquals("020117", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(Boolean.FALSE);
        assertEquals("010100", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write("kitten".getBytes());
        assertEquals("04066B697474656E", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write("kitten");
        assertEquals("0C066B697474656E", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write("f\u00fcnky");
        assertEquals("0C0666C3BC6E6B79", Util.encodeHex(buffer.toByteArray()));
    }

    public void testSimpleList() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(new ArrayList<Object>());
        assertEquals("30800000", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(Arrays.asList(new Object[] { 0x23,
                new byte[] { -1 }, Boolean.TRUE }));
        assertEquals("30800201230401FF0101FF0000",
                Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(Arrays.asList(new Object[] { 0x23,
                Arrays.asList(new Object[] { Integer.valueOf(10) }),
                Boolean.TRUE }));
        assertEquals("3080020123308002010A00000101FF0000",
                Util.encodeHex(buffer.toByteArray()));
    }

    public void testDefiniteLengthList() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer, false).write(new ArrayList<Object>());
        assertEquals("3000", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer, false).write(Arrays.asList(new Object[] {
                0x23, new byte[] { -1 }, Boolean.TRUE }));
        assertEquals("30090201230401FF0101FF",
                Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer, false).write(Arrays.asList(new Object[] {
                0x23, Arrays.asList(new Object[] { Integer.valueOf(10) }),
                Boolean.TRUE }));
        assertEquals("300B020123300302010A0101FF",
                Util.encodeHex(buffer.toByteArray()));
    }

    public void testEncodeData() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(new ArtificialData("vox".getBytes()));
        assertEquals("9F6403766F78", Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(new ArtificialData(
                new byte[] { -1, 0 }));
        assertEquals("9F6402FF00", Util.encodeHex(buffer.toByteArray()));
    }

    public void testEncodeSequence() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(new ArtificialSequence(Arrays
                .asList(new Integer[] { 3, 9 })));
        assertEquals("7F8148800201030201090000",
                Util.encodeHex(buffer.toByteArray()));

        buffer = new ByteArrayOutputStream();
        new BEROutputStream(buffer).write(new ArtificialSequence(Arrays
                .asList(new Object[] { Integer.valueOf(3), new byte[0],
                        Boolean.FALSE })));
        assertEquals("7F81488002010304000101000000",
                Util.encodeHex(buffer.toByteArray()));
    }

    public void testEncodeComplex() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        ArtificialSequence timestamp1 = new ArtificialSequence(
                Arrays.asList(new Long[] { 1081589747L, 0L }));
        ArtificialSequence timestamp2 = new ArtificialSequence(
                Arrays.asList(new Long[] { 1081589750L, 0L }));
        ArtificialSequence s = new ArtificialSequence(
                Arrays.asList(new Object[] {
                        "README",
                        "text/plain",
                        Arrays.asList(new Object[] { Long.valueOf(0664),
                                Long.valueOf(666), timestamp1, timestamp2 }),
                        Arrays.asList(new Object[] { "robey",
                                Arrays.asList(new Object[] { "robey" }) }), }));

        new BEROutputStream(buffer).write(s);

        String exp = "7F8148800C06524541444D450C0A746578742F706C61696E308002"
                + "0201B40202029A7F81488002044077BFF302010000007F81488002044077BF"
                + "F60201000000000030800C05726F62657930800C05726F626579000000000000";

        assertEquals(exp, Util.encodeHex(buffer.toByteArray()));

    }
}
