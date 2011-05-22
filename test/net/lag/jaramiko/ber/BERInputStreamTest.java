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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.List;

import junit.framework.TestCase;
import net.lag.jaramiko.Util;

public class BERInputStreamTest extends TestCase {
    public void testSimple() throws Exception {
        ByteArrayInputStream buffer = new ByteArrayInputStream(
                Util.decodeHex("020117"));
        assertEquals(BigInteger.valueOf(23), new BERInputStream(buffer).next());

        buffer = new ByteArrayInputStream(Util.decodeHex("0C03686579"));
        assertEquals("hey", new BERInputStream(buffer).next());

        buffer = new ByteArrayInputStream(Util.decodeHex("010100"));
        assertEquals(Boolean.FALSE, new BERInputStream(buffer).next());

        buffer = new ByteArrayInputStream(
                Util.decodeHex("040963616e646964617465"));
        assertEquals(Util.encodeHex("candidate".getBytes()),
                Util.encodeHex((byte[]) new BERInputStream(buffer).next()));
    }

    public void testDecodeSequence() throws Exception {
        ByteArrayInputStream buffer = new ByteArrayInputStream(
                Util.decodeHex("300902025A930403636174"));
        List<?> list = (List<?>) new BERInputStream(buffer).next();
        assertEquals(2, list.size());
        assertEquals(BigInteger.valueOf(23187), list.get(0));
        assertEquals("636174", Util.encodeHex((byte[]) list.get(1)));

        buffer = new ByteArrayInputStream(
                Util.decodeHex("308002025A9304036361740000"));
        list = (List<?>) new BERInputStream(buffer).next();
        assertEquals(2, list.size());
        assertEquals(BigInteger.valueOf(23187), list.get(0));
        assertEquals("636174", Util.encodeHex((byte[]) list.get(1)));
    }

    public void testDecodeNestedSequence() throws Exception {
        ByteArrayInputStream buffer = new ByteArrayInputStream(
                Util.decodeHex("3007300205000101FF"));
        List<?> list = (List<?>) new BERInputStream(buffer).next();
        assertEquals(2, list.size());
        List<?> list2 = (List<?>) list.get(0);
        assertEquals(1, list2.size());
        assertTrue(list2.get(0) == null);
        assertEquals(Boolean.TRUE, list.get(1));

        buffer = new ByteArrayInputStream(
                Util.decodeHex("30803080050000000101FF0000"));
        list = (List<?>) new BERInputStream(buffer).next();
        assertEquals(2, list.size());
        list2 = (List<?>) list.get(0);
        assertEquals(1, list2.size());
        assertTrue(list2.get(0) == null);
        assertEquals(Boolean.TRUE, list.get(1));
    }

    public void testDecodeComplexSequence() throws Exception {
        ArtificialSequence seq; // trick static code into registering
        seq = new ArtificialSequence(null);
        String data = "7F8148800C06524541444D450C0A746578742F706C61696E308002"
                + "0201B40202029A7F81488002044077BFF302010000007F81488002044077BF"
                + "F60201000000000030800C05726F62657930800C05726F626579000000000000";
        ByteArrayInputStream buffer = new ByteArrayInputStream(
                Util.decodeHex(data));
        seq = (ArtificialSequence) new BERInputStream(buffer).next();
        assertEquals(4, seq.mList.size());
        assertEquals("README", seq.mList.get(0));
        assertEquals("text/plain", seq.mList.get(1));
        List<?> list2 = (List<?>) seq.mList.get(2);
        assertEquals(4, list2.size());
        assertEquals(BigInteger.valueOf(436), list2.get(0));
        assertEquals(BigInteger.valueOf(666), list2.get(1));

        ArtificialSequence seq2 = (ArtificialSequence) list2.get(2);
        assertEquals(2, seq2.mList.size());
        assertEquals(BigInteger.valueOf(1081589747), seq2.mList.get(0));
        assertEquals(BigInteger.valueOf(0), seq2.mList.get(1));

        seq2 = (ArtificialSequence) list2.get(3);
        assertEquals(2, seq2.mList.size());
        assertEquals(BigInteger.valueOf(1081589750), seq2.mList.get(0));
        assertEquals(BigInteger.valueOf(0), seq2.mList.get(1));
    }

}

/*
 * 
 * 
 * def test_9_decode_complex_sequence(self): x =
 * ber.decode_stream(StringIO(EXAMPLE)) self.assert_(type(x) is Sequence)
 * self.assertEqual(4, len(x.seq)) self.assert_(type(x.seq[0]) is unicode)
 * self.assertEqual(u'README', x.seq[0]) self.assert_(type(x.seq[1]) is unicode)
 * self.assertEqual(u'text/plain', x.seq[1]) self.assert_(type(x.seq[2]) is
 * ber.BERList) self.assertEqual(4, len(x.seq[2]))
 * self.assert_(type(x.seq[2][0]) is long) self.assertEqual(436L, x.seq[2][0])
 * self.assert_(type(x.seq[2][1]) is long) self.assertEqual(666L, x.seq[2][1])
 * 
 * 
 * 
 * self.assert_(type(x.seq[3]) is ber.BERList) self.assertEqual(2,
 * len(x.seq[3])) self.assert_(type(x.seq[3][0]) is unicode)
 * self.assertEqual(u'robey', x.seq[3][0]) self.assert_(type(x.seq[3][1]) is
 * ber.BERList) self.assertEqual(1, len(x.seq[3][1]))
 * self.assert_(type(x.seq[3][1][0]) is unicode) self.assertEqual(u'robey',
 * x.seq[3][1][0])
 * 
 * timestamp1 = Sequence([ 1081589747L, 0L ]) timestamp2 = Sequence([
 * 1081589750L, 0L ]) self.assertEqual(Sequence([u'README', u'text/plain',
 * ber.BERList([0664L, 666L, timestamp1, timestamp2]), ber.BERList([u'robey',
 * ber.BERList([u'robey',])])]), x)
 */
