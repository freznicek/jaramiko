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

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import net.lag.crai.Crai;
import net.lag.crai.CraiDigest;


/**
 * Standard "group1" SHA1 key exchange, the one type required by the protocol.
 */
/* package */ class KexGroup1
    implements Kex
{
    public String
    getName ()
    {
        return "diffie-hellman-group1-sha1";
    }

    public void
    startKex (KexTransportInterface t, Crai crai)
        throws IOException
    {
        mTransport = t;
        mCrai = crai;

        generateX();
        if (mTransport.getServerKey() != null) {
            // (server mode)
            // compute f = g^x mod p, but don't send it yet
            mF = mCrai.modPow(G, mX, P);
            mTransport.registerMessageHandler(KEXDH_INIT, this);
            mTransport.expectPacket(KEXDH_INIT);
            return;
        }
        // compute e = g^x mod p (where g=2), and send it
        mE = mCrai.modPow(G, mX, P);
        Message m = new Message();
        m.putByte(KEXDH_INIT);
        m.putMPZ(mE);
        mTransport.sendMessage(m);
        mTransport.registerMessageHandler(KEXDH_REPLY, this);
        mTransport.expectPacket(KEXDH_REPLY);
    }

    public boolean
    handleMessage (byte ptype, Message m)
        throws IOException
    {
        if (ptype == KEXDH_INIT) {
            // server mode
            handleKexDHInit(m);
            return true;
        } else if (ptype == KEXDH_REPLY) {
            // client mode
            handleKexDHReply(m);
            return true;
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
            mCrai.getPRNG().getBytes(b);
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
        BigInteger k = mCrai.modPow(mE, mX, P);
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

        CraiDigest sha = mCrai.makeSHA1();
        byte[] data = hm.toByteArray();
        sha.update(data, 0, data.length);
        byte[] h = sha.finish();
        mTransport.setKH(k, h);

        // sign it
        byte[] sig = key.signSSHData(mCrai, h).toByteArray();
        Message rm = new Message();
        rm.putByte(KEXDH_REPLY);
        rm.putByteString(keyBytes);
        rm.putMPZ(mF);
        rm.putByteString(sig);
        mTransport.sendMessage(rm);
        mTransport.kexComplete();
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
        BigInteger k = mCrai.modPow(mF, mX, P);

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

        CraiDigest sha = mCrai.makeSHA1();
        byte[] data = hm.toByteArray();
        sha.update(data, 0, data.length);
        mTransport.setKH(k, sha.finish());
        mTransport.verifyKey(hostKey, sig);
        mTransport.kexComplete();
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

    private Crai mCrai;
    private KexTransportInterface mTransport;

    private BigInteger mX;
    private BigInteger mE;
    private BigInteger mF;
}
