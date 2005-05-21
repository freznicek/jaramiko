/*
 * Created on May 14, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Standard "group1" SHA1 key exchange, the one type required by the protocol.
 * 
 * @author robey
 */
public class KexGroup1
    implements Kex
{
    public String
    getName ()
    {
        return "diffie-hellman-group1-sha1";
    }
    
    public void
    startKex (TransportInterface t, SecureRandom r)
        throws IOException
    {
        mTransport = t;
        mRandom = r;
        
        generateX();
        if (mTransport.inServerMode()) {
            // compute f = g^x mod p, but don't send it yet
            mF = G.modPow(mX, P);
            mTransport.expectPacket(KEXDH_INIT);
            return;
        }
        // compute e = g^x mod p (where g=2), and send it
        mE = G.modPow(mX, P);
        Message m = new Message();
        m.putByte(KEXDH_INIT);
        m.putMPZ(mE);
        mTransport.sendMessage(m);
        mTransport.expectPacket(KEXDH_REPLY);
    }
    
    public void
    parseNext (byte ptype, Message m)
        throws IOException
    {
        if (mTransport.inServerMode() && (ptype == KEXDH_INIT)) {
            handleKexDHInit(m);
            return;
        } else if (! mTransport.inServerMode() && (ptype == KEXDH_REPLY)) {
            handleKexDHReply(m);
            return;
        }
        throw new SSHException("KexGroup1 asked to handle packet type " + MessageType.getDescription(ptype));
    }
    
    
    /*
     * Generate an "x" (1 < x < q), where q is (p-1)/2.
     * p is a 128-byte (1024-bit) number, where the first 64 bits are 1.
     * therefore q can be approximated as 2^1023.  we drop the subset of
     * potential x where the first 63 bits are 1, because some of those will
     * be larger than q (but this is a tiny tiny subset of potential x).
     */
    private void
    generateX ()
    {
        while (true) {
            byte[] b = new byte[128];
            mRandom.nextBytes(b);
            b[0] &= 0x7f;
            
            byte[] test = new byte[8];
            System.arraycopy(b, 0, test, 0, 8);
            if (! Arrays.equals(test, BAD1) && ! Arrays.equals(test, BAD2)) {
                mX = new BigInteger(b);
                return;
            }
        }
    }
    
    // server mode
    private void
    handleKexDHInit (Message m)
        throws IOException
    {
        mE = m.getMPZ();
        if ((mE.compareTo(BigInteger.ONE) < 0) || (mE.compareTo(P.subtract(BigInteger.ONE)) > 0)) {
            throw new SSHException("Client kex 'e' is out of range");
        }
        BigInteger k = mE.modPow(mX, P);
        PKey key = mTransport.getServerKey();
        byte[] keyBytes = key.toByteArray();
        
        // okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        Message hm = new Message();
        hm.putString(mTransport.getRemoteVersion());
        hm.putString(mTransport.getLocalVersion());
        hm.putByteString(mTransport.getRemoteKexInit());
        hm.putByteString(mTransport.getLocalKexInit());
        hm.putByteString(keyBytes);
        hm.putMPZ(mE);
        hm.putMPZ(mF);
        hm.putMPZ(k);
        
        byte[] h = null;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            h = sha.digest(hm.toByteArray());
            mTransport.setKH(k, h);
        } catch (NoSuchAlgorithmException x) {
            throw new SSHException("Unable to find SHA-1 algorithm in java");
        }
        
        // sign it
        byte[] sig = key.signSSHData(mRandom, h).toByteArray();
        Message rm = new Message();
        rm.putByte(KEXDH_REPLY);
        rm.putByteString(keyBytes);
        rm.putMPZ(mF);
        rm.putByteString(sig);
        mTransport.sendMessage(rm);
        mTransport.activateOutbound();
    }
    
    // client mode
    private void
    handleKexDHReply (Message m)
        throws IOException
    {
        byte[] hostKey = m.getByteString();
        mF = m.getMPZ();
        if ((mF.compareTo(BigInteger.ONE) < 0) || (mF.compareTo(P.subtract(BigInteger.ONE)) > 0)) {
            throw new SSHException("Server kex 'f' is out of range");
        }
        byte[] sig = m.getByteString();
        BigInteger k = mF.modPow(mX, P);

        // okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        Message hm = new Message();
        hm.putString(mTransport.getLocalVersion());
        hm.putString(mTransport.getRemoteVersion());
        hm.putByteString(mTransport.getLocalKexInit());
        hm.putByteString(mTransport.getRemoteKexInit());
        hm.putByteString(hostKey);
        hm.putMPZ(mE);
        hm.putMPZ(mF);
        hm.putMPZ(k);

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] h = sha.digest(hm.toByteArray());
            mTransport.setKH(k, h);
            mTransport.verifyKey(hostKey, sig);
            mTransport.activateOutbound();
        } catch (NoSuchAlgorithmException x) {
            throw new SSHException("Unable to find SHA-1 algorithm in java");
        }
    }
    
    
    public static final byte KEXDH_INIT = 30;
    public static final byte KEXDH_REPLY = 31;
    
    private static final BigInteger P =
        new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                       "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                       "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                       "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                       "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                       "FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger G = BigInteger.valueOf(2);
    
    private static final byte[] BAD1 = { 0, 0, 0, 0, 0, 0, 0, 0 };
    private static final byte[] BAD2 = { 0x7f, -1, -1, -1, -1, -1, -1, -1 };
    
    private SecureRandom mRandom;
    private TransportInterface mTransport;
    
    private BigInteger mX;
    private BigInteger mE;
    private BigInteger mF;
}
