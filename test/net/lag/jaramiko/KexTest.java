/*
 * Copyright (C) 2005-2007 Robey Pointer <robey@lag.net>
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

package net.lag.jaramiko;

import java.math.BigInteger;
import java.util.Arrays;
import junit.framework.TestCase;


/**
 * Test key-exchange implementations.
 */
public class KexTest
    extends TestCase
{
    public void
    testGroup1Client ()
        throws Exception
    {
        FakeKexTransport t = new FakeKexTransport();
        t.mServerMode = false;
        KexGroup1 kex = new KexGroup1();
        kex.startKex(t, new FakeCrai());
        assertTrue(Arrays.equals(EXP1, t.mMessage.toByteArray()));
        assertEquals(KexGroup1.KEXDH_REPLY, t.mExpect1);

        // fake "reply"
        Message m = new Message();
        m.putString("fake-host-key");
        m.putMPZ(BigInteger.valueOf(69));
        m.putString("fake-sig");
        m.rewind();
        kex.handleMessage(KexGroup1.KEXDH_REPLY, m);
        assertEquals(EXP1K, t.mK);
        assertTrue(Arrays.equals("fake-host-key".getBytes(), t.mVerifyKey));
        assertTrue(Arrays.equals("fake-sig".getBytes(), t.mVerifySig));
        assertTrue(Arrays.equals(EXP1H, t.mH));
        assertTrue(t.mActivated);
    }

    public void
    testGroup1Server ()
        throws Exception
    {
        FakeKexTransport t = new FakeKexTransport();
        t.mServerMode = true;
        KexGroup1 kex = new KexGroup1();
        kex.startKex(t, new FakeCrai());
        assertEquals(KexGroup1.KEXDH_INIT, t.mExpect1);

        Message m = new Message();
        m.putMPZ(BigInteger.valueOf(69));
        m.rewind();
        kex.handleMessage(KexGroup1.KEXDH_INIT, m);
        assertEquals(EXP1K, t.mK);
        assertTrue(Arrays.equals(EXP2H, t.mH));
        assertTrue(Arrays.equals(EXP2, t.mMessage.toByteArray()));
        assertTrue(t.mActivated);
    }

    public void
    testGexClient ()
        throws Exception
    {
        FakeKexTransport t = new FakeKexTransport();
        t.mServerMode = false;
        KexGex kex = new KexGex();
        kex.startKex(t, new FakeCrai());
        assertTrue(Arrays.equals(EXP3, t.mMessage.toByteArray()));
        assertEquals(KexGex.KEX_GEX_GROUP, t.mExpect1);

        Message m = new Message();
        m.putMPZ(FakeModulusPack.sP);
        m.putMPZ(BigInteger.valueOf(FakeModulusPack.sG));
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_GROUP, m);
        assertTrue(Arrays.equals(EXP3A, t.mMessage.toByteArray()));
        assertEquals(KexGex.KEX_GEX_REPLY, t.mExpect1);

        m = new Message();
        m.putString("fake-host-key");
        m.putMPZ(BigInteger.valueOf(69));
        m.putString("fake-sig");
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_REPLY, m);
        assertEquals(EXP1K, t.mK);
        assertTrue(Arrays.equals("fake-host-key".getBytes(), t.mVerifyKey));
        assertTrue(Arrays.equals("fake-sig".getBytes(), t.mVerifySig));
        assertTrue(Arrays.equals(EXP3H, t.mH));
        assertTrue(t.mActivated);
    }

    public void
    testGexOldClient ()
        throws Exception
    {
        FakeKexTransport t = new FakeKexTransport();
        t.mServerMode = false;
        KexGex kex = new KexGex();
        kex.mTestOldStyle = true;
        kex.startKex(t, new FakeCrai());
        assertTrue(Arrays.equals(EXP4, t.mMessage.toByteArray()));
        assertEquals(KexGex.KEX_GEX_GROUP, t.mExpect1);

        Message m = new Message();
        m.putMPZ(FakeModulusPack.sP);
        m.putMPZ(BigInteger.valueOf(FakeModulusPack.sG));
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_GROUP, m);
        assertTrue(Arrays.equals(EXP3A, t.mMessage.toByteArray()));
        assertEquals(KexGex.KEX_GEX_REPLY, t.mExpect1);

        m = new Message();
        m.putString("fake-host-key");
        m.putMPZ(BigInteger.valueOf(69));
        m.putString("fake-sig");
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_REPLY, m);
        assertEquals(EXP1K, t.mK);
        assertTrue(Arrays.equals("fake-host-key".getBytes(), t.mVerifyKey));
        assertTrue(Arrays.equals("fake-sig".getBytes(), t.mVerifySig));
        assertTrue(Arrays.equals(EXP4H, t.mH));
        assertTrue(t.mActivated);
    }

    public void
    testGexServer ()
        throws Exception
    {
        FakeKexTransport t = new FakeKexTransport();
        t.mServerMode = true;
        KexGex kex = new KexGex();
        kex.mModulusPack = new FakeModulusPack();
        kex.startKex(t, new FakeCrai());
        assertEquals(KexGex.KEX_GEX_REQUEST, t.mExpect1);
        assertEquals(KexGex.KEX_GEX_REQUEST_OLD, t.mExpect2);
        assertTrue(t.mMessage == null);

        Message m = new Message();
        m.putInt(1024);
        m.putInt(2048);
        m.putInt(4096);
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_REQUEST, m);
        assertTrue(Arrays.equals(EXP5, t.mMessage.toByteArray()));
        assertEquals(KexGex.KEX_GEX_INIT, t.mExpect1);
        assertEquals(0, t.mExpect2);

        m = new Message();
        m.putMPZ(BigInteger.valueOf(12345));
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_INIT, m);
        assertEquals(EXP5K, t.mK);
        assertTrue(Arrays.equals(EXP5H, t.mH));
        assertTrue(Arrays.equals(EXP5A, t.mMessage.toByteArray()));
        assertTrue(t.mActivated);
    }

    public void
    testGexServerWithOldClient ()
        throws Exception
    {
        FakeKexTransport t = new FakeKexTransport();
        t.mServerMode = true;
        KexGex kex = new KexGex();
        kex.mModulusPack = new FakeModulusPack();
        kex.startKex(t, new FakeCrai());
        assertEquals(KexGex.KEX_GEX_REQUEST, t.mExpect1);
        assertEquals(KexGex.KEX_GEX_REQUEST_OLD, t.mExpect2);
        assertTrue(t.mMessage == null);

        Message m = new Message();
        m.putInt(2048);
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_REQUEST_OLD, m);
        assertTrue(Arrays.equals(EXP6, t.mMessage.toByteArray()));
        assertEquals(KexGex.KEX_GEX_INIT, t.mExpect1);
        assertEquals(0, t.mExpect2);

        m = new Message();
        m.putMPZ(BigInteger.valueOf(12345));
        m.rewind();
        kex.handleMessage(KexGex.KEX_GEX_INIT, m);
        assertEquals(EXP5K, t.mK);
        assertTrue(Arrays.equals(EXP6H, t.mH));
        assertTrue(Arrays.equals(EXP5A, t.mMessage.toByteArray()));
        assertTrue(t.mActivated);

    }


    private static final byte[] EXP1 =
        Util.decodeHex("1E000000807E2DDB1743F3487D6545F04F1C8476092FB912B013" +
                       "626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00" +
                       "299913503456983FFB9178D3CD79EB6D55522418A8ABF6537587" +
                       "2E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225" +
                       "FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE" +
                       "9208D4");

    private static final byte[] EXP1H =
        Util.decodeHex("03079780F3D3AD0B3C6DB30C8D21685F367A86D2");

    private static final BigInteger EXP1K =
        new BigInteger("1473034331770871643980731003287197245944836419509417" +
                       "9797249681733965528989482751523943515690110179031004" +
                       "0491093756126855058819112741014414155450396541024743" +
                       "7647224050161698879969974413529107048831474828428349" +
                       "6055223852115360852283821334858541043710301057312858" +
                       "051901453919067023103730011648890038847384890504");

    private static final byte[] EXP2 =
        Util.decodeHex("1F0000000866616B652D6B6579000000807E2DDB1743F3487D65" +
                       "45F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B" +
                       "9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79" +
                       "EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66" +
                       "A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383" +
                       "F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D7369" +
                       "67");

    private static final byte[] EXP2H =
        Util.decodeHex("B16BF34DD10945EDE84E9C1EF24A14BFDC843389");

    private static final byte[] EXP3 =
        Util.decodeHex("22000004000000080000002000");

    private static final byte[] EXP3A =
        Util.decodeHex("20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013" +
                       "626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00" +
                       "299913503456983FFB9178D3CD79EB6D55522418A8ABF6537587" +
                       "2E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225" +
                       "FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE" +
                       "9208D4");

    private static final byte[] EXP3H =
        Util.decodeHex("A265563F2FA87F1A89BF007EE90D58BE2E4A4BD0");

    private static final byte[] EXP4 =
        Util.decodeHex("1E00000800");

    private static final byte[] EXP4H =
        Util.decodeHex("807F87B269EF7AC5EC7E75676808776A27D5864C");

    private static final byte[] EXP5 =
        Util.decodeHex("1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                       "80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E34" +
                       "04DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                       "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE38" +
                       "6BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFF" +
                       "FFFFFFFF0000000102");

    private static final BigInteger EXP5K =
        new BigInteger("6759299501359613787603346002839333995187904114037851" +
                       "0871612128162185209509220726296697886624612526735888" +
                       "3480204987164827576778489594200737201604911143191630" +
                       "7886290540002095919638694792638840668728890156419207" +
                       "1077389283980347784184487280885335302632305026248574" +
                       "716290537036069329724382811853044654824945750581");

    private static final byte[] EXP5H =
        Util.decodeHex("CE754197C21BF3452863B4F44D0B3951F12516EF");

    private static final byte[] EXP5A =
        Util.decodeHex("210000000866616B652D6B6579000000807E2DDB1743F3487D65" +
                       "45F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B" +
                       "9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79" +
                       "EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66" +
                       "A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383" +
                       "F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D7369" +
                       "67");

    private static final byte[] EXP6 =
        Util.decodeHex("1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                       "80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E34" +
                       "04DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                       "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE38" +
                       "6BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFF" +
                       "FFFFFFFF0000000102");

    private static final byte[] EXP6H =
        Util.decodeHex("B41A06B2E59043CEFC1AE16EC31F1E2D12EC455B");
}
