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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.util.Arrays;

import junit.framework.TestCase;
import net.lag.crai.Crai;
import net.lag.crai.CraiDigest;
import net.lag.craijce.CraiJCE;

/**
 * Test PKey methods.
 */
public class PKeyTest extends TestCase {

    public void testGenerateKeyBytes() throws Exception {
        CraiDigest md5 = new FakeCrai().makeMD5();
        byte[] salt = { 1, 2, 3, 4 };
        byte[] key = PKey.generateKeyBytes(md5, salt,
                "happy birthday".getBytes(), 30);

        String exps = "61E1F272F4C1C4561586BD322498C0E924672780F47BB37DDA7D54019E64";
        byte[] exp = Util.decodeHex(exps);
        assertTrue(Arrays.equals(exp, key));
    }

    public void testLoadRSA() throws Exception {
        PKey rsa = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_rsa.key"), null);
        assertEquals("ssh-rsa", rsa.getSSHName());
        assertEquals(RSA_FINGERPRINT, Util.encodeHex(rsa.getFingerprint()));
        assertEquals(PUB_RSA, rsa.getBase64());
        assertEquals(1024, rsa.getBits());
    }

    public void testLoadRSAPassword() throws Exception {
        PKey rsa = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_rsa_password.key"), "television");
        assertEquals("ssh-rsa", rsa.getSSHName());
        assertEquals(RSA_FINGERPRINT, Util.encodeHex(rsa.getFingerprint()));
        assertEquals(PUB_RSA, rsa.getBase64());
        assertEquals(1024, rsa.getBits());
    }

    public void testSaveRSA() throws Exception {
        PKey rsa = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_rsa.key"), null);
        assertEquals(RSA_FINGERPRINT, Util.encodeHex(rsa.getFingerprint()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        rsa.writePrivateKeyToStream(out, null);

        FileInputStream in = new FileInputStream("test/test_rsa.key");
        ByteArrayOutputStream exp = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (true) {
            int n = in.read(buffer);
            if (n <= 0) {
                break;
            }
            exp.write(buffer, 0, n);
        }

        assertEquals(Util.encodeHex(out.toByteArray()),
                Util.encodeHex(exp.toByteArray()));
    }

    public void testSaveRSAPassword() throws Exception {
        PKey rsa = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_rsa_password.key"), "television");
        assertEquals(RSA_FINGERPRINT, Util.encodeHex(rsa.getFingerprint()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        rsa.writePrivateKeyToStream(out, "skeletor");

        rsa = PKey.readPrivateKeyFromStream(
                new ByteArrayInputStream(out.toByteArray()), "skeletor");
        assertEquals(RSA_FINGERPRINT, Util.encodeHex(rsa.getFingerprint()));
    }

    public void testLoadDSS() throws Exception {
        PKey dss = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss.key"), null);
        assertEquals("ssh-dss", dss.getSSHName());
        assertEquals(DSS_FINGERPRINT, Util.encodeHex(dss.getFingerprint()));
        assertEquals(PUB_DSS, dss.getBase64());
        assertEquals(1024, dss.getBits());

        dss = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss2.key"), null);
        assertEquals("ssh-dss", dss.getSSHName());
        assertEquals(1024, dss.getBits());
    }

    public void testLoadDSSPassword() throws Exception {
        PKey dss = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss_password.key"), "television");
        assertEquals("ssh-dss", dss.getSSHName());
        assertEquals(DSS_FINGERPRINT, Util.encodeHex(dss.getFingerprint()));
        assertEquals(PUB_DSS, dss.getBase64());
        assertEquals(1024, dss.getBits());
    }

    public void testSaveDSS() throws Exception {
        PKey dss = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss.key"), null);
        assertEquals(DSS_FINGERPRINT, Util.encodeHex(dss.getFingerprint()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        dss.writePrivateKeyToStream(out, null);

        FileInputStream in = new FileInputStream("test/test_dss.key");
        ByteArrayOutputStream exp = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (true) {
            int n = in.read(buffer);
            if (n <= 0) {
                break;
            }
            exp.write(buffer, 0, n);
        }

        assertEquals(Util.encodeHex(out.toByteArray()),
                Util.encodeHex(exp.toByteArray()));
    }

    public void testSaveDSSPassword() throws Exception {
        PKey dss = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss_password.key"), "television");
        assertEquals(DSS_FINGERPRINT, Util.encodeHex(dss.getFingerprint()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        dss.writePrivateKeyToStream(out, "skeletor");

        dss = PKey.readPrivateKeyFromStream(
                new ByteArrayInputStream(out.toByteArray()), "skeletor");
        assertEquals(DSS_FINGERPRINT, Util.encodeHex(dss.getFingerprint()));
    }

    // verify that the public & private keys compare equal
    public void testCompareRSA() throws Exception {
        PKey rsa = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_rsa.key"), null);
        assertEquals(rsa, rsa);
        PKey pub = PKey.createFromData(rsa.toByteArray());
        assertTrue(rsa.canSign());
        assertTrue(!pub.canSign());
        assertEquals(rsa, pub);
    }

    public void testCompareDSS() throws Exception {
        PKey dss = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss.key"), null);
        assertEquals(dss, dss);
        PKey pub = PKey.createFromData(dss.toByteArray());
        assertTrue(dss.canSign());
        assertTrue(!pub.canSign());
        assertEquals(dss, pub);
    }

    public void testSignRSA() throws Exception {
        PKey rsa = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_rsa.key"), null);
        Message m = rsa.signSSHData(new CraiJCE(), "ice weasels".getBytes());
        m.rewind();
        assertEquals("ssh-rsa", m.getString());
        assertEquals(SIGNED_RSA, Util.encodeHex(m.getByteString()));

        m.rewind();
        PKey pub = PKey.createFromData(rsa.toByteArray());
        assertTrue(pub.verifySSHSignature(new CraiJCE(),
                "ice weasels".getBytes(), m));
    }

    public void testSignDSS() throws Exception {
        PKey dss = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss.key"), null);
        Message m = dss.signSSHData(new CraiJCE(), "ice weasels".getBytes());
        m.rewind();
        assertEquals("ssh-dss", m.getString());
        /*
         * DSS uses randomness in its key signatures, so we can't know the exact
         * signature without providing a fake source of randomness. in the
         * post-Crai world, providing that source is really hard.
         */
        // assertEquals(SIGNED_DSS, Util.encodeHex(m.getByteString()));

        m.rewind();
        PKey pub = PKey.createFromData(dss.toByteArray());
        assertTrue(pub.verifySSHSignature(new CraiJCE(),
                "ice weasels".getBytes(), m));
    }

    public void testGenerateRSA() throws Exception {
        Crai crai = new CraiJCE();
        RSAKey rsa = RSAKey.generate(crai, 1024);

        Message m = rsa.signSSHData(crai, "jerri blank".getBytes());
        m.rewind();
        assertTrue(rsa.verifySSHSignature(crai, "jerri blank".getBytes(), m));
    }

    public void testGenerateDSA() throws Exception {
        Crai crai = new CraiJCE();
        DSSKey dss = DSSKey.generate(crai, 1024);

        Message m = dss.signSSHData(crai, "jerri blank".getBytes());
        m.rewind();
        assertTrue(dss.verifySSHSignature(crai, "jerri blank".getBytes(), m));
    }

    public void testBuildRSA() throws Exception {
        Crai crai = new CraiJCE();
        BigInteger n = new BigInteger(TEST_RSA_N, 16);
        BigInteger d = new BigInteger(TEST_RSA_D, 16);
        BigInteger e = new BigInteger(TEST_RSA_E, 16);

        RSAKey pubkey = RSAKey.build(e, n);
        RSAKey privkey = RSAKey.build(e, d, n, null, null);

        Message m = privkey.signSSHData(crai, "jerri blank".getBytes());
        m.rewind();
        assertTrue(pubkey.verifySSHSignature(crai, "jerri blank".getBytes(), m));
    }

    public void testBuildDSS() throws Exception {
        Crai crai = new CraiJCE();
        BigInteger g = new BigInteger(TEST_DSS_G, 16);
        BigInteger p = new BigInteger(TEST_DSS_P, 16);
        BigInteger q = new BigInteger(TEST_DSS_Q, 16);
        BigInteger y = new BigInteger(TEST_DSS_Y, 16);
        BigInteger x = new BigInteger(TEST_DSS_X, 16);

        DSSKey pubkey = DSSKey.build(p, q, g, y);
        DSSKey privkey = DSSKey.build(p, q, g, y, x);

        Message m = privkey.signSSHData(crai, "jerri blank".getBytes());
        m.rewind();
        assertTrue(pubkey.verifySSHSignature(crai, "jerri blank".getBytes(), m));
    }

    private static final String RSA_FINGERPRINT = "60733844CB5186657FDEDAA22B5A57D5";
    private static final String DSS_FINGERPRINT = "4478F0B9A23CC5182009FF755BC1D26C";

    private static final String PUB_RSA = "AAAAB3NzaC1yc2EAAAABIwAAAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKT"
            + "k4dmzkQY2yAMs6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeT"
            + "d+yv4q+V2PvZv3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3"
            + "y21tH4c=";
    private static final String PUB_DSS = "AAAAB3NzaC1kc3MAAACBAOeBpgNnfRzr/twmAQRu2XwWAp3CFtrVnug6s6fgwj/o"
            + "LjYbVtjAy6pl/h0EKCWx2rf1IetyNsTxWrniA9I6HeDj65X1FyDkg6g8tvCnaNB8"
            + "Xp/UUhuzHuGsMIipRxBxw9LF608EqZcj1E3ytktoW5B5OcjrkEoz3xG7C+rpIjYv"
            + "AAAAFQDwz4UnmsGiSNu5iqjn3uTzwUpshwAAAIEAkxfFeY8P2wZpDjX0MimZl5wk"
            + "oFQDL25cPzGBuB4OnB8NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+Ngw3qIch/WgR"
            + "mMHy4kBq1SsXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ej"
            + "g4Ok10+XFDxlqZo8Y+wAAACARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV"
            + "1BVYd0lYukmnjO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9"
            + "kUgyB7+NwacIBlXa8cMDL7Q/69o0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwj"
            + "QgE=";

    private static final String SIGNED_RSA = "20D78A3121CBF79212F2A48937F578AFE616B625B9973DA2CD5FCA2021734CAD"
            + "34738F207728E2941508D891407A8583BF183795DC541A9B88296C73CA38B404"
            + "F156B9F2429D521B2929B44FFDC92DAF47D2407630F363450CD91D43860F1C70"
            + "E2931234F3ACC50A2F14506659F188EEC14AE9D19C4E46F00E476F3874F144A8";

    private static final String TEST_RSA_N = "9b684587c9f15e268904797a201530daa38dee4c4856757ec07ed8a41250f7ee"
            + "eba3756458dc55fc343ddff4f8ff4c16dcba26b88dffa9c59f353cf66f1d50b3"
            + "e01ecc2078b0f82afec76e59354a4db0299ceaa6a56c0a5265ec14b39a94f7f6"
            + "0e2d50f9290eadc6be8547c9e1d322bbd09e45a9da33fb93ddfa9d254c1736eb";
    private static final String TEST_RSA_E = "10001";
    private static final String TEST_RSA_D = "8394054ab2f06986b6fbd2de53cb9d5180a8eada2b65089608e55d078d7a8071"
            + "09919c131a2973a3d5978dc71c0b0ba14fc14c8775b2c14b5141021ca4776d9b"
            + "89b1fe5c40b40cd2d8bc1d4085c09d3da364ea8708a71843dd6bc13eae59aad6"
            + "da69eda55e87db04313683d22c1898665a414af0568a35e0ffd4e36e63adac1";

    private static final String TEST_DSS_G = "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d078267"
            + "5159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e1"
            + "3c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243b"
            + "cca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a";
    private static final String TEST_DSS_P = "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669"
            + "455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b7"
            + "6b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb"
            + "83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7";
    private static final String TEST_DSS_Q = "9760508f15230bccb292b982a2eb840bf0581cf5";
    private static final String TEST_DSS_Y = "65a65aadf4db090574f5e24f684a472fdde100ecef4cf624dc3a5fb1838f1056"
            + "8eafc7c12a3fa07f74b44789468ff73e334558fda135be0042094ce2dab055fb"
            + "224109993ecbadcfed223ec28940295f71c501ac5f902ed1526ca6b02f4eadc4"
            + "cb1c3bc4411d8abc2267fa5f80a1142dc17bafb897188760a5a751fbb0dfcc80";
    private static final String TEST_DSS_X = "746248f49944ab19cc412f7c69fe57efed225ca3";
}
