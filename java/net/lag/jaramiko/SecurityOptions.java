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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * Simple object containing the security preferences of an SSH {@link Transport}
 * . These are lists of acceptable ciphers, digests, key types, and key exchange
 * algorithms, listed in order of preference.
 * 
 * <p>
 * Changing the contents and/or order of these fields affects the underlying
 * {@link Transport}, but only if you change them before starting the session.
 * If you try to add an algorithm that jaramiko doesn't recognize, an
 * IllegalArgumentException will be thrown.
 */
public final class SecurityOptions {
    /* package */
    SecurityOptions(String[] knownCiphers, String[] knownMacs,
            String[] knownKeys, String[] knownKex, String[] knownCompressions) {
        mKnownCiphers = knownCiphers;
        mKnownMacs = knownMacs;
        mKnownKeys = knownKeys;
        mKnownKex = knownKex;
        mKnownCompressions = knownCompressions;

        mCiphers = new ArrayList(Arrays.asList(knownCiphers));
        mMacs = new ArrayList(Arrays.asList(knownMacs));
        mKeys = new ArrayList(Arrays.asList(knownKeys));
        mKex = new ArrayList(Arrays.asList(knownKex));
        mCompressions = new ArrayList(Arrays.asList(knownCompressions));
    }

    public void setCiphers(List ciphers) {
        setList(mCiphers, ciphers, mKnownCiphers);
    }

    public void setDigests(List macs) {
        setList(mMacs, macs, mKnownMacs);
    }

    public void setKeys(List keys) {
        setList(mKeys, keys, mKnownKeys);
    }

    public void setKex(List kex) {
        setList(mKex, kex, mKnownKex);
    }

    public void setCompressions(List compressions) {
        setList(mCompressions, compressions, mKnownCompressions);
    }

    public List getCiphers() {
        return new ArrayList(mCiphers);
    }

    public List getDigests() {
        return new ArrayList(mMacs);
    }

    public List getKeys() {
        return new ArrayList(mKeys);
    }

    public List getKex() {
        return new ArrayList(mKex);
    }

    public List getCompressions() {
        return new ArrayList(mCompressions);
    }

    private void setList(List mine, List theirs, String[] valid) {
        mine.clear();
        for (Iterator i = theirs.iterator(); i.hasNext();) {
            String x = (String) i.next();
            if (!Arrays.asList(valid).contains(x)) {
                throw new IllegalArgumentException();
            }
            mine.add(x);
        }
    }

    private String[] mKnownCiphers;
    private String[] mKnownMacs;
    private String[] mKnownKeys;
    private String[] mKnownKex;
    private String[] mKnownCompressions;

    private List mCiphers;
    private List mMacs;
    private List mKeys;
    private List mKex;
    private List mCompressions;
}
