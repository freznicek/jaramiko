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

/**
 * Stubbed-out KexTransportInterface for testing key-exchange implementations.
 */
public class FakeKexTransport implements KexTransportInterface {
    @Override
    public String getRemoteVersion() {
        return "SSH-2.0-lame";
    }

    @Override
    public String getLocalVersion() {
        return "SSH-2.0-paramiko_1.0";
    }

    @Override
    public byte[] getRemoteKexInit() {
        return "remote-kex-init".getBytes();
    }

    @Override
    public byte[] getLocalKexInit() {
        return "local-kex-init".getBytes();
    }

    @Override
    public void registerMessageHandler(byte ptype, MessageHandler handler) {
        // pass
    }

    @Override
    public void expectPacket(byte expect) {
        mExpect1 = expect;
        mExpect2 = 0;
    }

    @Override
    public void expectPacket(byte expect1, byte expect2) {
        mExpect1 = expect1;
        mExpect2 = expect2;
    }

    @Override
    public void sendMessage(Message m) {
        mMessage = m;
    }

    @Override
    public PKey getServerKey() {
        if (mServerMode) {
            return new FakeKey();
        } else {
            return null;
        }
    }

    @Override
    public void verifyKey(byte[] key, byte[] sig) {
        mVerifyKey = key;
        mVerifySig = sig;
    }

    @Override
    public void setKH(BigInteger k, byte[] h) {
        mK = k;
        mH = h;
    }

    @Override
    public void kexComplete() {
        mActivated = true;
    }

    @Override
    public LogSink getLog() {
        return new NullLog();
    }

    public Message mMessage;
    public Message mUserMessage;
    public byte mExpect1;
    public byte mExpect2;
    public BigInteger mK;
    public byte[] mH;
    public byte[] mVerifyKey;
    public byte[] mVerifySig;
    public boolean mActivated = false;
    public boolean mServerMode = false;
}
