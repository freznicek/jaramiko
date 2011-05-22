/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
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

import junit.framework.*;

import net.lag.craijce.CraiJCE;
import net.lag.jaramiko.ber.*;


public class AllTests
{

    public static Test
    suite ()
    {
        TestSuite ts = new TestSuite();
        ClientTransport.setCrai(new CraiJCE());

        ts.addTestSuite(UtilTest.class);

        ts.addTestSuite(MessageTest.class);
        ts.addTestSuite(PacketizerTest.class);
        ts.addTestSuite(KexTest.class);
        ts.addTestSuite(PKeyTest.class);
        ts.addTestSuite(TransportTest.class);
        ts.addTestSuite(ChannelTest.class);
        ts.addTestSuite(ModulusPackTest.class);
        ts.addTestSuite(HostKeysTest.class);

        ts.addTestSuite(TagTest.class);
        ts.addTestSuite(BERInputStreamTest.class);
        ts.addTestSuite(BEROutputStreamTest.class);

        return ts;
    }

    public static void
    main (String[] args)
    {
        Test suite = suite();
        TestResult r = new TestResult();
        TestListener listener = new TestListener() {
            public void addError(Test test, java.lang.Throwable t) {
                System.err.println("ERROR.");
            }

            public void addFailure(Test test, AssertionFailedError t) {
                System.err.println("FAILURE.");
            }

            public void endTest(Test test) {
                System.err.println("<- " + test);
            }

            public void startTest(Test test) {
                System.err.println("-> " + test);
            }
        };
        r.addListener(listener);

        suite.run(r);
    }
}
