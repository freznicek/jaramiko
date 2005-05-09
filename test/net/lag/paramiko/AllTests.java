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
        //ts.addTestSuite(WeirdNetTest.class);

        return ts;
    }
}
