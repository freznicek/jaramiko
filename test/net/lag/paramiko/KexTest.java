/*
 * Created on May 14, 2005
 */

package net.lag.paramiko;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import junit.framework.TestCase;

/**
 * @author robey
 */
public class KexTest
    extends TestCase
{
    static class FakeRandom
        extends SecureRandom
    {
        public void
        nextBytes (byte[] b)
        {
            for (int i = 0; i < b.length; i++) {
                b[i] = (byte)0xcc;
            }
        }
        
        private static final long serialVersionUID = 0;
    }
    
    
    static class FakeTransport
        implements TransportInterface
    {
        public void
        sendMessage (Message m)
        {
            mMessage = m;
        }
        
        public void
        setKH (BigInteger k, byte[] h)
        {
            mK = k;
            mH = h;
        }
        
        public void
        activateOutbound ()
        {
            mActivated = true;
        }
        
        public String
        getRemoteVersion ()
        {
            return "SSH-2.0-lame";
        }
        
        public String
        getLocalVersion ()
        {
            return "SSH-2.0-paramiko_1.0";
        }
        
        public byte[]
        getRemoteKexInit ()
        {
            return "remote-kex-init".getBytes();
        }
        
        public byte[]
        getLocalKexInit ()
        {
            return "local-kex-init".getBytes();
        }
        
        public void
        verifyKey (byte[] key, byte[] sig)
        {
            mVerifyKey = key;
            mVerifySig = sig;
        }
        
        public void
        expectPacket (byte expect)
        {
            mExpect = expect;
        }
        
        public boolean
        inServerMode ()
        {
            return mServerMode;
        }
        
        
        public Message mMessage;
        public byte mExpect;
        public BigInteger mK;
        public byte[] mH;
        public byte[] mVerifyKey;
        public byte[] mVerifySig;
        public boolean mActivated = false;
        public boolean mServerMode = false;
    }
    
    
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
        kex.parseNext(KexGroup1.KEXDH_REPLY, m);
        assertEquals(EXP1K, t.mK);
        assertTrue(Arrays.equals("fake-host-key".getBytes(), t.mVerifyKey));
        assertTrue(Arrays.equals("fake-sig".getBytes(), t.mVerifySig));
        for (int i = 0; i < EXP1H.length; i++) {
            if (EXP1H[i] != t.mH[i]) {
                System.err.println("bad " + i + ": " + EXP1H[i] + " != " + t.mH[i]);
            }
        }
        assertTrue(Arrays.equals(EXP1H, t.mH));
    }
    
    private static final byte[] EXP1 = {
        0x1e, 0, 0, 0, (byte)0x80, 0x7e, 0x2d, (byte)0xdb, 0x17, 0x43,
        (byte)0xf3, 0x48, 0x7d, 0x65, 0x45, (byte)0xf0, 0x4f, 0x1c, (byte)0x84,
        0x76, 9, 0x2f, (byte)0xb9, 0x12, (byte)0xb0, 0x13, 0x62, 0x6a,
        (byte)0xb5, (byte)0xbc, (byte)0xeb, 0x76, 0x42, 0x57, (byte)0xd8,
        (byte)0x8b, (byte)0xba, 0x64, 0x24, 0x3b, (byte)0x9f, 0x34, (byte)0x8d,
        (byte)0xf7, (byte)0xb4, 0x1b, (byte)0x8c, (byte)0x81, 0x4a, (byte)0x99,
        0x5e, 0, 0x29, (byte)0x99, 0x13, 0x50, 0x34, 0x56, (byte)0x98, 0x3f,
        (byte)0xfb, (byte)0x91, 0x78, (byte)0xd3, (byte)0xcd, 0x79, (byte)0xeb,
        0x6d, 0x55, 0x52, 0x24, 0x18, (byte)0xa8, (byte)0xab, (byte)0xf6,
        0x53, 0x75, (byte)0x87, 0x2e, 0x55, (byte)0x93, (byte)0x8a, (byte)0xb9,
        (byte)0x9a, (byte)0x84, (byte)0xa0, (byte)0xb5, (byte)0xfc, (byte)0x8a,
        0x1e, (byte)0xcc, 0x66, (byte)0xa7, (byte)0xc3, 0x76, 0x6e, 0x7e, 0x0f,
        (byte)0x80, (byte)0xb7, (byte)0xce, 0x2c, (byte)0x92, 0x25, (byte)0xfc,
        0x2d, (byte)0xd6, (byte)0x83, (byte)0xf4, 0x76, 0x42, 0x44, (byte)0xb7,
        0x29, 0x63, (byte)0xbb, (byte)0xb3, (byte)0x83, (byte)0xf5, 0x29,
        (byte)0xdc, (byte)0xf0, (byte)0xc5, (byte)0xd1, 0x77, 0x40, (byte)0xb8,
        (byte)0xa2, (byte)0xad, (byte)0xbe, (byte)0x92, 8, (byte)0xd4
    };
    
    private static final byte[] EXP1H = {
        3, 7, (byte)0x97, (byte)0x80, (byte)0xf3, (byte)0xd3, (byte)0xad, 0xb,
        (byte)0x3c, 0x6d, (byte)0xb3, 12, (byte)0x8d, 0x21, 0x68, 0x5f,
        0x36, 0x7a, (byte)0x86, (byte)0xd2
    };
    
    private static final BigInteger EXP1K =
        new BigInteger("1473034331770871643980731003287197245944836419509417" +
                       "9797249681733965528989482751523943515690110179031004" +
                       "0491093756126855058819112741014414155450396541024743" +
                       "7647224050161698879969974413529107048831474828428349" +
                       "6055223852115360852283821334858541043710301057312858" +
                       "051901453919067023103730011648890038847384890504");

}
