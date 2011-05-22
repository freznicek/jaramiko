/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
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
 *
 *
 * Created on May 10, 2005
 */

package net.lag.jaramiko;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import junit.framework.TestCase;
import net.lag.crai.CraiCipher;
import net.lag.crai.CraiCipherAlgorithm;
import net.lag.crai.CraiDigest;

/**
 * @author robey
 */
public class PacketizerTest extends TestCase {
    public void testWrite() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        Packetizer p = new Packetizer(is, os, new FakeRandom());

        CraiCipher c = new FakeCrai().getCipher(CraiCipherAlgorithm.AES_CBC);
        c.initEncrypt(KEY, IV);
        CraiDigest mac = new FakeCrai().makeSHA1HMAC(MAC_KEY);

        p.setOutboundCipher(c, 16, mac, 12);

        Message m = new Message();
        m.putByte((byte) 100);
        m.putInt(100);
        m.putInt(1);
        m.putInt(900);
        p.write(m);

        byte[] buf = os.toByteArray();
        // 32 + 12 bytes of MAC = 44
        assertEquals(44, buf.length);
        byte[] got = new byte[16];
        System.arraycopy(buf, 0, got, 0, 16);
        assertTrue(Arrays.equals(got, EXP_WRITE));
    }

    public void testRead() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(DATA_READ);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        Packetizer p = new Packetizer(is, os, new FakeRandom());

        CraiCipher c = new FakeCrai().getCipher(CraiCipherAlgorithm.AES_CBC);
        c.initDecrypt(KEY, IV);
        CraiDigest mac = new FakeCrai().makeSHA1HMAC(MAC_KEY);

        p.setInboundCipher(c, 16, mac, 12);

        Message m = p.read();
        assertEquals(13, m.getLength());
        assertEquals(100, m.getByte());
        assertEquals(100, m.getInt());
        assertEquals(1, m.getInt());
        assertEquals(900, m.getInt());
    }

    private final static byte[] KEY = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0 };
    private final static byte[] IV = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
    private final static byte[] MAC_KEY = { 31, 31, 31, 31, 31, 31, 31, 31, 31,
            31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31 };

    private final static byte[] EXP_WRITE = { 0x43, (byte) 0x91, (byte) 0x97,
            (byte) 0xbd, 0x5b, 0x50, (byte) 0xac, 0x25, (byte) 0x87,
            (byte) 0xc2, (byte) 0xc4, 0x6b, (byte) 0xc7, (byte) 0xe9, 0x38,
            (byte) 0xc0 };

    private final static byte[] DATA_READ = { 0x43, (byte) 0x91, (byte) 0x97,
            (byte) 0xbd, 0x5b, 0x50, (byte) 0xac, 0x25, (byte) 0x87,
            (byte) 0xc2, (byte) 0xc4, 0x6b, (byte) 0xc7, (byte) 0xe9, 0x38,
            (byte) 0xc0, (byte) 0x90, (byte) 0xd2, 0x16, 0x56, 0x0d, 0x71,
            0x73, 0x61, 0x38, 0x7c, 0x4c, 0x3d, (byte) 0xfb, (byte) 0x97, 0x7d,
            (byte) 0xe2, 0x6e, 0x03, (byte) 0xb1, (byte) 0xa0, (byte) 0xc2,
            0x1c, (byte) 0xd6, 0x41, 0x41, 0x4c, (byte) 0xb4, 0x59 };
}
