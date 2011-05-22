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
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;
import net.lag.jaramiko.Util;

public class TagTest extends TestCase {
    public void testUniversal() throws Exception {
        Tag t = Tag
                .fromStream(new ByteArrayInputStream(Util.decodeHex("0000")));
        assertEquals(Tag.UNIVERSAL, t.getDomain());
        assertEquals(0, t.getType());
        assertFalse(t.isContainer());
        assertTrue(t.hasSize());
        assertEquals(0, t.getSize());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("0000", Util.encodeHex(out.toByteArray()));
    }

    public void testApplication() throws Exception {
        Tag t = Tag
                .fromStream(new ByteArrayInputStream(Util.decodeHex("7E00")));
        assertEquals(Tag.APPLICATION, t.getDomain());
        assertEquals(30, t.getType());
        assertTrue(t.isContainer());
        assertTrue(t.hasSize());
        assertEquals(0, t.getSize());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("7E00", Util.encodeHex(out.toByteArray()));
    }

    public void testContext() throws Exception {
        Tag t = Tag
                .fromStream(new ByteArrayInputStream(Util.decodeHex("8100")));
        assertEquals(Tag.CONTEXT, t.getDomain());
        assertEquals(1, t.getType());
        assertFalse(t.isContainer());
        assertTrue(t.hasSize());
        assertEquals(0, t.getSize());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("8100", Util.encodeHex(out.toByteArray()));
    }

    public void testPrivate() throws Exception {
        Tag t = Tag
                .fromStream(new ByteArrayInputStream(Util.decodeHex("C900")));
        assertEquals(Tag.PRIVATE, t.getDomain());
        assertEquals(9, t.getType());
        assertFalse(t.isContainer());
        assertTrue(t.hasSize());
        assertEquals(0, t.getSize());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("C900", Util.encodeHex(out.toByteArray()));
    }

    public void testLongTag() throws Exception {
        Tag t = Tag.fromStream(new ByteArrayInputStream(Util
                .decodeHex("9F822301")));
        assertEquals(Tag.CONTEXT, t.getDomain());
        assertEquals(0x123, t.getType());
        assertFalse(t.isContainer());
        assertTrue(t.hasSize());
        assertEquals(1, t.getSize());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("9F822301", Util.encodeHex(out.toByteArray()));

        t = Tag.fromStream(new ByteArrayInputStream(Util
                .decodeHex("9FE5BFD76E00")));
        assertEquals(0xcafebee, t.getType());

        out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("9FE5BFD76E00", Util.encodeHex(out.toByteArray()));
    }

    public void testLongSize() throws Exception {
        Tag t = Tag.fromStream(new ByteArrayInputStream(Util
                .decodeHex("C0820103")));
        assertEquals(Tag.PRIVATE, t.getDomain());
        assertEquals(0, t.getType());
        assertFalse(t.isContainer());
        assertTrue(t.hasSize());
        assertEquals(259, t.getSize());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("C0820103", Util.encodeHex(out.toByteArray()));

        t = Tag.fromStream(new ByteArrayInputStream(Util.decodeHex("308181")));
        assertEquals(Tag.UNIVERSAL, t.getDomain());
        assertEquals(16, t.getType());
        assertTrue(t.isContainer());
        assertTrue(t.hasSize());
        assertEquals(129, t.getSize());

        out = new ByteArrayOutputStream();
        t.write(out);
        assertEquals("308181", Util.encodeHex(out.toByteArray()));
    }

    public void testErrors() throws Exception {
        try {
            Tag.fromStream(new ByteArrayInputStream(Util.decodeHex("0480")));
            fail("expected exception");
        } catch (BERException x) {}

        // truncated tag type
        try {
            Tag.fromStream(new ByteArrayInputStream(Util.decodeHex("3F")));
            fail("expected exception");
        } catch (BERException x) {}

        // truncated tag is missing length field
        try {
            Tag.fromStream(new ByteArrayInputStream(Util.decodeHex("30")));
            fail("expected exception");
        } catch (BERException x) {}

        // truncated length
        try {
            Tag.fromStream(new ByteArrayInputStream(Util.decodeHex("3081")));
            fail("expected exception");
        } catch (BERException x) {}

        // tag type too long
        try {
            Tag.fromStream(new ByteArrayInputStream(Util
                    .decodeHex("9F8CD7FAF53E00")));
            fail("expected exception");
        } catch (BERException x) {}

        // size field too long
        try {
            Tag.fromStream(new ByteArrayInputStream(Util
                    .decodeHex("C0850000000000")));
            fail("expected exception");
        } catch (BERException x) {}
    }

    public void testCompareAndHash() throws Exception {
        Tag t = Tag.create(Tag.CONTEXT, 13, 0);
        assertEquals(Tag.create(Tag.CONTEXT, 13, 0), t);
        assertEquals(Tag.fromStream(new ByteArrayInputStream(Util
                .decodeHex("8D00"))), t);

        assertEquals(t.hashCode(), Tag.create(Tag.CONTEXT, 13, 0).hashCode());
        Map<Tag, Integer> m = new HashMap<Tag, Integer>();
        m.put(t, new Integer(23));
        assertEquals(23, (int) m.get(Tag.create(Tag.CONTEXT, 13, 0)));
    }
}
