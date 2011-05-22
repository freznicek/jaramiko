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

import net.lag.crai.Crai;
import net.lag.crai.CraiDigest;

/* package */class KexGex implements Kex {
    public KexGex() {
        mModulusPack = BaseTransport.getModulusPack();
    }

    public String getName() {
        return "diffie-hellman-group-exchange-sha1";
    }

    public void startKex(KexTransportInterface t, Crai crai) throws IOException {
        mTransport = t;
        mCrai = crai;

        if (t.getServerKey() != null) {
            // server mode
            t.expectPacket(KEX_GEX_REQUEST, KEX_GEX_REQUEST_OLD);
            return;
        }

        /*
         * request a bit range: we accept (mMinBits) to (mMaxBits), but prefer
         * (mPreferredBits). according to the spec, we shoudn't pull the minimum
         * up above 1024.
         */
        Message m = new Message();
        if (mTestOldStyle) {
            // only used for unit tests; we shouldn't ever send this.
            m.putByte(KEX_GEX_REQUEST_OLD);
            m.putInt(mPreferredBits);
        } else {
            m.putByte(KEX_GEX_REQUEST);
            m.putInt(mMinBits);
            m.putInt(mPreferredBits);
            m.putInt(mMaxBits);
        }
        t.sendMessage(m);
        t.expectPacket(KEX_GEX_GROUP);
    }

    /**
     * Handle an SSH protocol message and return true if the message was
     * understood, or false if it wasn't (and wasn't handled). This is part of
     * jaramiko's internal implementation.
     * 
     * @param ptype
     *            message type
     * @param m
     *            message
     * @return true if the message was handled; false otherwise
     * @throws IOException
     *             if an exception occurred
     */
    public boolean handleMessage(byte ptype, Message m) throws IOException {
        switch (ptype) {
        case KEX_GEX_REQUEST:
            parseRequest(m);
            return true;
        case KEX_GEX_GROUP:
            parseGroup(m);
            return true;
        case KEX_GEX_INIT:
            parseInit(m);
            return true;
        case KEX_GEX_REPLY:
            parseReply(m);
            return true;
        case KEX_GEX_REQUEST_OLD:
            parseRequestOld(m);
            return true;
        }

        throw new SSHException("KexGex asked to handle packet type "
                + MessageType.getDescription(ptype));
    }

    // server mode:

    private void parseRequest(Message m) throws IOException {
        int minBits = m.getInt();
        int preferredBits = m.getInt();
        int maxBits = m.getInt();

        // smoosh the user's preferred size into our own limits
        if (preferredBits > mMaxBits) {
            preferredBits = mMaxBits;
        }
        if (preferredBits < mMinBits) {
            preferredBits = mMinBits;
        }

        /*
         * fix min/max if they're inconsistent. technically, we could just pout
         * and hang up, but there's no harm in giving them the benefit of the
         * doubt and just picking a bitsize for them.
         */
        if (minBits > preferredBits) {
            minBits = preferredBits;
        }
        if (maxBits < preferredBits) {
            maxBits = preferredBits;
        }

        // now save a copy.
        mMinBits = minBits;
        mPreferredBits = preferredBits;
        mMaxBits = maxBits;

        // generate prime
        if (mModulusPack.size() == 0) {
            throw new SSHException("Can't do server-side gex; no modulus list");
        }

        mTransport.getLog().debug(
                "Picking p (" + mMinBits + " <= " + mPreferredBits + " <= "
                        + mMaxBits + " bits)");
        ModulusPack.ModulusPair mod = mModulusPack.get(mCrai, mMinBits,
                mPreferredBits, mMaxBits);
        mG = BigInteger.valueOf(mod.mGenerator);
        mP = mod.mModulus;

        m = new Message();
        m.putByte(KEX_GEX_GROUP);
        m.putMPZ(mP);
        m.putMPZ(mG);
        mTransport.sendMessage(m);
        mTransport.expectPacket(KEX_GEX_INIT);
    }

    private void parseRequestOld(Message m) throws IOException {
        // same as above, but without min_bits or max_bits (used by older
        // clients like putty).
        int preferredBits = m.getInt();

        // smoosh the user's preferred size into our own limits
        if (preferredBits > mMaxBits) {
            preferredBits = mMaxBits;
        }
        if (preferredBits < mMinBits) {
            preferredBits = mMinBits;
        }

        // now save a copy.
        mPreferredBits = preferredBits;

        // generate prime
        if (mModulusPack.size() == 0) {
            throw new SSHException("Can't do server-side gex; no modulus list");
        }

        mTransport.getLog().debug("Picking p (~ " + mPreferredBits + " bits)");
        ModulusPack.ModulusPair mod = mModulusPack.get(mCrai, mMinBits,
                mPreferredBits, mMaxBits);
        mG = BigInteger.valueOf(mod.mGenerator);
        mP = mod.mModulus;

        m = new Message();
        m.putByte(KEX_GEX_GROUP);
        m.putMPZ(mP);
        m.putMPZ(mG);
        mTransport.sendMessage(m);
        mTransport.expectPacket(KEX_GEX_INIT);
        mUseOldStyle = true;
    }

    private void parseInit(Message m) throws IOException {
        mE = m.getMPZ();
        if ((mE.compareTo(BigInteger.ONE) < 0)
                || (mE.compareTo(mP.subtract(BigInteger.ONE)) > 0)) {
            throw new SSHException("Client kex 'e' is out of range");
        }
        generateX();
        mF = mG.modPow(mX, mP);
        BigInteger k = mE.modPow(mX, mP);
        PKey key = mTransport.getServerKey();
        byte[] keyBytes = key.toByteArray();

        // okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || min
        // || n || max || p || g || e || f || K)
        Message hm = new Message();
        hm.putString(mTransport.getRemoteVersion());
        hm.putString(mTransport.getLocalVersion());
        hm.putByteString(mTransport.getRemoteKexInit());
        hm.putByteString(mTransport.getLocalKexInit());
        hm.putByteString(keyBytes);
        if (!mUseOldStyle) {
            hm.putInt(mMinBits);
        }
        hm.putInt(mPreferredBits);
        if (!mUseOldStyle) {
            hm.putInt(mMaxBits);
        }
        hm.putMPZ(mP);
        hm.putMPZ(mG);
        hm.putMPZ(mE);
        hm.putMPZ(mF);
        hm.putMPZ(k);

        CraiDigest sha = mCrai.makeSHA1();
        byte[] data = hm.toByteArray();
        sha.update(data, 0, data.length);
        byte[] h = sha.finish();
        mTransport.setKH(k, h);

        // sign it.
        byte[] sig = key.signSSHData(mCrai, h).toByteArray();
        Message rm = new Message();
        rm.putByte(KEX_GEX_REPLY);
        rm.putByteString(keyBytes);
        rm.putMPZ(mF);
        rm.putByteString(sig);
        mTransport.sendMessage(rm);
        mTransport.kexComplete();
    }

    // client mode:

    private void parseGroup(Message m) throws IOException {
        mP = m.getMPZ();
        mG = m.getMPZ();

        // reject if p's bit length < 1024 or > 8192
        int bitlen = mP.bitLength();
        if ((bitlen < 1024) || (bitlen > 8192)) {
            throw new SSHException(
                    "Server-generated gex p (don't ask) is out of range ("
                            + bitlen + " bits)");
        }
        mTransport.getLog().debug("Got server p (" + bitlen + " bits)");
        generateX();

        // now compute e = g^x mod p.
        mE = mG.modPow(mX, mP);
        Message rm = new Message();
        rm.putByte(KEX_GEX_INIT);
        rm.putMPZ(mE);
        mTransport.sendMessage(rm);
        mTransport.expectPacket(KEX_GEX_REPLY);
    }

    private void parseReply(Message m) throws IOException {
        byte[] hostKey = m.getByteString();
        mF = m.getMPZ();
        byte[] sig = m.getByteString();
        if ((mF.compareTo(BigInteger.ONE) < 0)
                || (mF.compareTo(mP.subtract(BigInteger.ONE)) > 0)) {
            throw new SSHException("Server kex 'f' is out of range");
        }
        BigInteger k = mF.modPow(mX, mP);

        // okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || min
        // || n || max || p || g || e || f || K)
        Message hm = new Message();
        hm.putString(mTransport.getLocalVersion());
        hm.putString(mTransport.getRemoteVersion());
        hm.putByteString(mTransport.getLocalKexInit());
        hm.putByteString(mTransport.getRemoteKexInit());
        hm.putByteString(hostKey);
        if (!mTestOldStyle) {
            hm.putInt(mMinBits);
        }
        hm.putInt(mPreferredBits);
        if (!mTestOldStyle) {
            hm.putInt(mMaxBits);
        }
        hm.putMPZ(mP);
        hm.putMPZ(mG);
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

    // generate an "x" (1 < x < (p-1)/2).
    private void generateX() {
        mQ = mP.subtract(BigInteger.ONE).shiftRight(1);
        while (true) {
            mX = Util.rollRandom(mCrai, mQ);
            if (mX.compareTo(BigInteger.ONE) > 0) {
                return;
            }
        }
    }

    private KexTransportInterface mTransport;
    private Crai mCrai;
    protected ModulusPack mModulusPack;

    private int mMinBits = 1024;
    private int mMaxBits = 8192;
    private int mPreferredBits = 2048;
    /* package */boolean mTestOldStyle = false;
    private boolean mUseOldStyle = false;

    private BigInteger mP;
    private BigInteger mQ;
    private BigInteger mG;
    private BigInteger mX;
    private BigInteger mE;
    private BigInteger mF;

    protected static final byte KEX_GEX_REQUEST_OLD = 30;
    protected static final byte KEX_GEX_GROUP = 31;
    protected static final byte KEX_GEX_INIT = 32;
    protected static final byte KEX_GEX_REPLY = 33;
    protected static final byte KEX_GEX_REQUEST = 34;
}
