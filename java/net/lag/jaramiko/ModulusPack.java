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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.*;

import net.lag.crai.Crai;


/**
 * Convenience object for holding the contents of an openssh 'moduli' file,
 * which contains pre-generated primes of various bit sizes, for use in
 * group-exchange key negotiation (aka "kex-gex").
 */
/* package */ class ModulusPack
{
    public static class ModulusPair
    {
        public
        ModulusPair (int generator, BigInteger modulus)
        {
            mGenerator = generator;
            mModulus = modulus;
        }


        public int mGenerator;
        public BigInteger mModulus;
    }


    public
    ModulusPack ()
    {
        mDiscarded = new ArrayList();
        // map of: bit length -> List<ModulusPair>
        mPack = new HashMap();
    }

    private boolean
    parseModulus (String line)
    {
        // timestamp, mod_type, tests, tries, size, generator, modulus
        String[] elems = Util.splitString(line, " ", 7);
        if (elems.length < 7) {
            return false;
        }
        int modType = Util.fuzzyInt(elems[1]);
        int tests = Util.fuzzyInt(elems[2]);
        int tries = Util.fuzzyInt(elems[3]);
        int size = Util.fuzzyInt(elems[4]);
        int generator = Util.fuzzyInt(elems[5]);
        BigInteger modulus = new BigInteger(elems[6], 16);

        /* weed out primes that aren't at least:
         * type 2 (meets basic structural requirements)
         * test 4 (more than just a small-prime sieve)
         * tries < 100 if test & 4 (at least 100 tries of miller-rabin)
         */
        if ((modType < 2) || (tests < 4) || (((tests & 4) != 0) && (tests < 8) && (tries < 100))) {
            mDiscarded.add(modulus);
            return false;
        }
        if (generator == 0) {
            generator = 2;
        }

        /* there's a bug in the ssh "moduli" file (yeah, i know: shock!
         * dismay! call cnn!) where it understates the bit lengths of these
         * primes by 1. this is okay.
         */
        int bl = modulus.bitLength();
        if ((bl != size) && (bl != size + 1)) {
            mDiscarded.add(modulus);
            return false;
        }
        List list = (List) mPack.get(Integer.valueOf(bl));
        if (list == null) {
            list = new ArrayList();
            mPack.put(Integer.valueOf(bl), list);
        }
        list.add(new ModulusPair(generator, modulus));
        return true;
    }

    public int
    readFromStream (InputStream in)
        throws IOException
    {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        int count = 0;

        while (true) {
            String line = reader.readLine();
            if (line == null) {
                return count;
            }
            if ((line.length() == 0) || line.startsWith("#")) {
                continue;
            }
            if (parseModulus(line)) {
                count++;
            }
        }
    }

    public int
    readStandardResource ()
    {
        /* this requires a bit of care. many embedded JVMs won't have the
         * ability to load files this way.
         */
        ClassLoader loader = getClass().getClassLoader();
        if (loader == null) {
            return 0;
        }
        try {
            Method method = loader.getClass().getMethod("getResourceAsStream", new Class[] { String.class });
            if (method == null) {
                return 0;
            }
            Object stream = method.invoke(loader, new Object[] { "resources/moduli" });
            return readFromStream((InputStream) stream);
        } catch (Exception x) {
            return 0;
        }
    }

    public ModulusPair
    get (Crai crai, int min, int prefer, int max)
        throws SSHException
    {
        List bitsizesList = new ArrayList(mPack.keySet());
        Collections.sort(bitsizesList);
        if (bitsizesList.size() == 0) {
            throw new SSHException("no moduli available");
        }
        int[] bitsizes = new int[bitsizesList.size()];
        for (int i = 0; i < bitsizes.length; i++) {
            bitsizes[i] = ((Integer) bitsizesList.get(i)).intValue();
        }

        int good = -1;

        // find nearest bitsize >= preferred
        for (int i = 0; i < bitsizes.length; i++) {
            int b = bitsizes[i];
            if ((b >= prefer) && (b < max) && ((b < good) || (good == -1))) {
                good = b;
            }
        }

        // if that failed, find greatest bitsize >= min
        if (good == -1) {
            for (int i = 0; i < bitsizes.length; i++) {
                int b = bitsizes[i];
                if ((b >= min) && (b < max) && (b > good)) {
                    good = b;
                }
            }
        }

        if (good == -1) {
            /* their entire (min, max) range has no intersection with our
             * range. if their range is below ours, pick the smallest.
             * otherwise pick the largest. it'll be out of their range
             * requirement either way, but we'll be sending them the closest
             * one we have.
             */
            good = bitsizes[0];
            if (min > good) {
                good = bitsizes[bitsizes.length - 1];
            }
        }

        // now pick a random modulus of this bitsize.
        List list = (List) mPack.get(Integer.valueOf(good));
        int n = Util.rollRandom(crai, BigInteger.valueOf(list.size())).intValue();
        return (ModulusPair) list.get(n);
    }

    public List
    getDiscarded ()
    {
        return mDiscarded;
    }

    public int
    size ()
    {
        int size = 0;
        for (Iterator iter = mPack.keySet().iterator(); iter.hasNext(); ) {
            Integer key = (Integer) iter.next();
            size += ((List) mPack.get(key)).size();
        }
        return size;
    }


    private List mDiscarded;    // List<BigInteger>
    private Map mPack;          // Map<int, List<ModulusPair>>
}
