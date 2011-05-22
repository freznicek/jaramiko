/*
 * Copyright (C) 2007 Robey Pointer <robey@lag.net>
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

import net.lag.crai.Crai;

public class FakeModulusPack extends ModulusPack {
    @Override
    public ModulusPair get(Crai crai, int min, int prefer, int max)
            throws SSHException {
        return new ModulusPair(sG, sP);
    }

    @Override
    public int size() {
        return 1;
    }

    private static final String P_TEXT = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088"
            + "A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B30"
            + "2B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63"
            + "7ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE64928"
            + "6651ECE65381FFFFFFFFFFFFFFFF";
    public static final BigInteger sP = new BigInteger(P_TEXT, 16);
    public static final int sG = 2;
}
