/*
 * Created on May 7, 2005
 */

package net.lag.paramiko;

import junit.framework.*;


/**
 * @author robey
 */
public class AllTests
{

    public static Test
    suite ()
    {
        TestSuite ts = new TestSuite();

        ts.addTestSuite(MessageTest.class);
        ts.addTestSuite(PacketizerTest.class);
        ts.addTestSuite(KexTest.class);
        ts.addTestSuite(PKeyTest.class);
        ts.addTestSuite(TransportTest.class);

        ts.addTestSuite(WeirdNetTest.class);
        
        return ts;
    }
}
