/*
 * Created on May 7, 2005
 */

package net.lag.paramiko;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import junit.framework.TestCase;


/**
 * @author robey
 */
public class MessageTest
    extends TestCase
{
    public
    MessageTest ()
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 100; i++) {
            sb.append("xxxxxxxxxx");
        }
        mKiloX = sb.toString();
    }

    public void
    testEncode1 ()
    {
        Message m = new Message();
        m.putInt(23);
        m.putInt(123789456);
        m.putString("q");
        m.putString("hello");
        m.putBytes(new byte[] { 23, 9, 4 });
        m.putString(mKiloX);

        byte[] buf = m.toByteArray();
        assertEquals(EXP1.length + 1000, m.getPosition());
        byte[] buf1 = new byte[EXP1.length];
        System.arraycopy(buf, 0, buf1, 0, EXP1.length);
        byte[] buf2 = new byte[1000];
        System.arraycopy(buf, EXP1.length, buf2, 0, 1000);

        assertTrue(Arrays.equals(buf1, EXP1));
        assertTrue(Arrays.equals(buf2, mKiloX.getBytes()));
    }
    
    public void
    testDecode1 ()
    {
        byte[] buf = new byte[EXP1.length + 1000];
        System.arraycopy(EXP1, 0, buf, 0, EXP1.length);
        System.arraycopy(mKiloX.getBytes(), 0, buf, EXP1.length, 1000);

        Message m = new Message(buf);
        assertEquals(23, m.getInt());
        assertEquals(123789456, m.getInt());
        assertEquals("q", m.getString());
        assertEquals("hello", m.getString());
        assertTrue(Arrays.equals(new byte[] { 23, 9, 4 }, m.getBytes(3)));
        assertEquals(mKiloX, m.getString());
    }
    
    public void
    testEncode2 ()
    {
        Message m = new Message();
        m.putBoolean(true);
        m.putBoolean(false);
        m.putByte((byte) 0xf3);
        m.putList(Arrays.asList(new String[] { "huey", "dewey", "louie" }));

        byte[] buf = m.toByteArray();
        assertEquals(EXP2.length, m.getPosition());
        byte[] answer = new byte[EXP2.length];
        System.arraycopy(buf, 0, answer, 0, EXP2.length);
        assertTrue(Arrays.equals(answer, EXP2));
    }
    
    public void
    testDecode2 ()
    {
        byte[] buf = new byte[EXP2.length];
        System.arraycopy(EXP2, 0, buf, 0, EXP2.length);
        Message m = new Message(buf);
        assertEquals(true, m.getBoolean());
        assertEquals(false, m.getBoolean());
        assertEquals((byte)0xf3, m.getByte());
        List l = m.getList();
        assertEquals(3, l.size());
        assertEquals("huey", l.get(0).toString());
        assertEquals("dewey", l.get(1).toString());
        assertEquals("louie", l.get(2).toString());
    }
    
    public void
    testEncode3 ()
    {
        Message m = new Message();
        m.putInt64(5L);
        m.putInt64(0xf5e4d3c2b109L);
        m.putMPZ(BigInteger.valueOf(17));
        m.putMPZ(BigInteger.valueOf(0xf5e4d3c2b109L));
        m.putMPZ(BigInteger.valueOf(-0x65e4d3c2b109L));
        
        byte[] buf = m.toByteArray();
        assertEquals(EXP3.length, m.getPosition());
        byte[] answer = new byte[EXP3.length];
        System.arraycopy(buf, 0, answer, 0, EXP3.length);
        assertTrue(Arrays.equals(answer, EXP3));
    }

    public void
    testDecode3 ()
    {
        byte[] buf = new byte[EXP3.length];
        System.arraycopy(EXP3, 0, buf, 0, EXP3.length);
        Message m = new Message(buf);
        assertEquals(5L, m.getInt64());
        assertEquals(0xf5e4d3c2b109L, m.getInt64());
        assertEquals(BigInteger.valueOf(17), m.getMPZ());
        assertEquals(BigInteger.valueOf(0xf5e4d3c2b109L), m.getMPZ());
        assertEquals(BigInteger.valueOf(-0x65e4d3c2b109L), m.getMPZ());
    }
    
    public void
    testPacketize ()
    {
        Message m = new Message();
        m.putInt(23);
        m.packetize(new SecureRandom(), 8);
        
        byte[] buf = m.toByteArray();
        assertEquals(16, m.getPosition());
        for (int i = 0; i < EXP4.length; i++) {
            assertEquals(EXP4[i], buf[i]);
        }
    }
    

    private String mKiloX;
    
    private static final byte[] EXP1 =
        { 0, 0, 0, 0x17, 7, 0x60, (byte)0xe0, (byte)0x90,
          0, 0, 0, 1, (byte)'q', 0, 0, 0, 5, (byte)'h',
          (byte)'e', (byte)'l', (byte)'l', (byte)'o', 23, 9, 4,
          0, 0, 3, (byte)0xe8 };
    
    private static final byte[] EXP2 =
        { 1, 0, (byte)0xf3, 0, 0, 0, 0x10, (byte)'h', (byte)'u',
          (byte)'e', (byte)'y', (byte)',', (byte)'d', (byte)'e',
          (byte)'w', (byte)'e', (byte)'y', (byte)',', (byte)'l',
          (byte)'o', (byte)'u', (byte)'i', (byte)'e' };
    
    private static final byte[] EXP3 =
        { 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, (byte)0xf5, (byte)0xe4,
          (byte)0xd3, (byte)0xc2, (byte)0xb1, 9, 0, 0, 0, 1, 17,
          0, 0, 0, 7, 0, (byte)0xf5, (byte)0xe4, (byte)0xd3,
          (byte)0xc2, (byte)0xb1, 9, 0, 0, 0, 6, (byte)0x9a,
          0x1b, 0x2c, 0x3d, 0x4e, (byte)0xf7 };
    
    private static final byte[] EXP4 =
        { 0, 0, 0, 12, 7, 0, 0, 0, 23 }; 
}
