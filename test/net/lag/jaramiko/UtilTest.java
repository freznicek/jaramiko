/*
 * Copyright (C) 2007  Danger, Inc.
 * 3101 Park Blvd, Palo Alto CA 94306
 */

package net.lag.jaramiko;

import junit.framework.TestCase;


public class UtilTest
    extends TestCase
{
    public void
    testStrip ()
    {
        assertEquals("hello", Util.strip("  hello"));
        assertEquals("hello", Util.strip("hello\t\t"));
        assertEquals("hello", Util.strip("\thello  "));
        assertEquals("", Util.strip("       "));
    }
}
