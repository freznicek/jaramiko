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
 * Created on May 14, 2005
 */

package net.lag.paramiko;

import java.math.BigInteger;
import java.util.Arrays;
import junit.framework.TestCase;

/**
 * @author robey
 */
public class KexTest
    extends TestCase
{
    public void
    testGroup1Client ()
        throws Exception
    {
        FakeTransport t = new FakeTransport();
        t.mServerMode = false;
        KexGroup1 kex = new KexGroup1();
        kex.startKex(t, new FakeRandom());
        assertTrue(Arrays.equals(EXP1, t.mMessage.toByteArray()));
        assertEquals(KexGroup1.KEXDH_REPLY, t.mExpect);
        
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
    }
    
    public void
    testGroup1Server ()
        throws Exception
    {
        FakeTransport t = new FakeTransport();
        t.mServerMode = true;
        KexGroup1 kex = new KexGroup1();
        kex.startKex(t, new FakeRandom());
        assertEquals(KexGroup1.KEXDH_INIT, t.mExpect);
        
        Message m = new Message();
        m.putMPZ(BigInteger.valueOf(69));
        m.rewind();
        kex.handleMessage(KexGroup1.KEXDH_INIT, m);
        assertEquals(EXP1K, t.mK);
        assertTrue(Arrays.equals(EXP2H, t.mH));
        assertTrue(Arrays.equals(EXP2, t.mMessage.toByteArray()));
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
}
