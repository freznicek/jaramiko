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
import java.io.OutputStream;
import java.math.BigInteger;

import net.lag.crai.Crai;
import net.lag.crai.CraiPrivateKey;
import net.lag.crai.CraiPublicKey;

/**
 * Stub out PKey for some tests.
 */
public class FakeKey extends PKey {
    @Override
    public Message signSSHData(Crai crai, byte[] data) {
        Message m = new Message();
        m.putBytes("fake-sig".getBytes());
        return m;
    }

    @Override
    public boolean verifySSHSignature(Crai crai, byte[] data, Message sig) {
        return false;
    }

    @Override
    protected void buildFromBER(BigInteger[] ints) {
        // pass
    }

    @Override
    protected void buildFromMessage(Message m) {
        // pass
    }

    @Override
    public void writePrivateKeyToStream(OutputStream os, String password)
            throws IOException {
        // pass
    }

    @Override
    public byte[] toByteArray() {
        return "fake-key".getBytes();
    }

    @Override
    public boolean canSign() {
        return true;
    }

    @Override
    public int getBits() {
        return 0;
    }

    @Override
    public String getSSHName() {
        return "none";
    }

    @Override
    public CraiPublicKey toPublicKey(Crai crai) {
        return null;
    }

    @Override
    public CraiPrivateKey toPrivateKey(Crai crai) {
        return null;
    }
}
