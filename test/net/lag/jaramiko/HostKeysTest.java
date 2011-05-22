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

import java.io.ByteArrayInputStream;
import java.util.Map;

import junit.framework.TestCase;

public class HostKeysTest extends TestCase {
    private final static String TEST_HOSTS_FILE = "# comment here.\n"
            + "secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TV"
            + "xET6lkpKhOk5r9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+"
            + "9jtoyyDOOVX4UIDV9G11Ml8om3D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS"
            + "2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=\n"
            + "happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZ"
            + "DB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS"
            + "1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYq"
            + "WIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=\n";

    private final static String KEYBLOB = "AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6g"
            + "kpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5y"
            + "mME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/Qps"
            + "FH+Pc2M=";

    private final static String KEYBLOB_DSS = "AAAAB3NzaC1kc3MAAACBAOeBpgNnfRzr/twmAQRu2XwWAp3CFtrVnug6s6fgwj/o"
            + "LjYbVtjAy6pl/h0EKCWx2rf1IetyNsTxWrniA9I6HeDj65X1FyDkg6g8tvCnaNB8"
            + "Xp/UUhuzHuGsMIipRxBxw9LF608EqZcj1E3ytktoW5B5OcjrkEoz3xG7C+rpIjYv"
            + "AAAAFQDwz4UnmsGiSNu5iqjn3uTzwUpshwAAAIEAkxfFeY8P2wZpDjX0MimZl5wk"
            + "oFQDL25cPzGBuB4OnB8NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+Ngw3qIch/WgR"
            + "mMHy4kBq1SsXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ej"
            + "g4Ok10+XFDxlqZo8Y+wAAACARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV"
            + "1BVYd0lYukmnjO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9"
            + "kUgyB7+NwacIBlXa8cMDL7Q/69o0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwj"
            + "QgE=";

    public void testLoad() throws Exception {
        HostKeys hk = new HostKeys();
        hk.load(new ByteArrayInputStream(TEST_HOSTS_FILE.getBytes()));
        assertEquals(2, hk.size());
        assertEquals(1, hk.lookup("secure.example.com").size());
        assertEquals(0, hk.lookup("not.example.com").size());
        PKey key = (PKey) hk.lookup("secure.example.com").get("ssh-rsa");
        assertEquals("E6684DB30E109B67B70FF1DC5C7F1363",
                Util.encodeHex(key.getFingerprint()).toUpperCase());
    }

    public void testAdd() throws Exception {
        HostKeys hk = new HostKeys();
        hk.load(new ByteArrayInputStream(TEST_HOSTS_FILE.getBytes()));
        PKey key = PKey.createFromData(Base64.decode(KEYBLOB));
        hk.add("|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c=",
                key);
        assertEquals(3, hk.size());
        PKey key2 = (PKey) hk.lookup("foo.example.com").get("ssh-rsa");
        assertEquals("7EC91BB336CB6D810B124B1353C32396",
                Util.encodeHex(key2.getFingerprint()));
        assertTrue(hk.check("foo.example.com", key));
    }

    public void testMultiKeys() throws Exception {
        HostKeys hk = new HostKeys();
        hk.load(new ByteArrayInputStream(TEST_HOSTS_FILE.getBytes()));
        PKey rkey = PKey.createFromData(Base64.decode(KEYBLOB));
        hk.add("|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c=",
                rkey);
        PKey dkey = PKey.createFromData(Base64.decode(KEYBLOB_DSS));
        hk.add("foo.example.com", dkey);

        assertEquals(4, hk.size());
        Map m = hk.lookup("foo.example.com");
        assertEquals(2, m.size());
        assertEquals(
                Util.encodeHex(((PKey) m.get("ssh-rsa")).getFingerprint()),
                Util.encodeHex(rkey.getFingerprint()));
        assertEquals(
                Util.encodeHex(((PKey) m.get("ssh-dss")).getFingerprint()),
                Util.encodeHex(dkey.getFingerprint()));
    }
}
