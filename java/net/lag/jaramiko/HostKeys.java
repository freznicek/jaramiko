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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.lag.crai.Crai;
import net.lag.crai.CraiDigest;

/**
 * Representation of an openssh-style "known_hosts" file. Host keys can be read
 * from one or more files, and then individual hosts can be looked up to verify
 * server keys during SSH negotiation.
 */
public class HostKeys {
    // representation of a host in an openssh-style "known hosts" file
    private static class Entry {
        public boolean mValid = false;
        public PKey mKey = null;
        public String mHostnames[] = null;

        /**
         * Parse the given line of text to find the names for a host, the type
         * of key given, and the key data. The line should be in the key file
         * format used by openssh.
         * 
         * <p>
         * Lines are expected to not have leading or trailing whitespace.
         * 
         * @param line
         *            text line from a known_hosts file
         * @return a new HostKeys.Entry
         * @throws SSHException
         *             if the line is formatted incorrectly, the key type isn't
         *             recognized, or the key data is mangled
         */
        public static Entry fromLine(String line) throws SSHException {
            String[] fields = Util.splitString(line, " ", 3);
            if (fields.length != 3) {
                throw new SSHException("Invalid line");
            }

            PKey key = null;
            if (fields[1].equals("ssh-rsa")) {
                key = PKey.createFromBase64(fields[2]);
            } else if (fields[1].equals("ssh-dss")) {
                key = PKey.createFromBase64(fields[2]);
            } else {
                throw new SSHException("Unknown key type");
            }

            Entry entry = new Entry();
            entry.mHostnames = Util.splitString(fields[0], ",");
            entry.mKey = key;
            entry.mValid = true;
            return entry;
        }

        public String toLine() {
            if (!mValid) {
                return "# invalid key.\n";
            }
            return Util.join(mHostnames, ",") + " " + mKey.getSSHName() + " "
                    + mKey.getBase64() + "\n";
        }

        @Override
        public String toString() {
            if (!mValid) {
                return "<HostKeys.Entry invalid>";
            }
            return "<HostKeys.Entry hostname=" + Util.join(mHostnames, ",")
                    + " key=" + mKey + ">";
        }
    }

    /*
     * must be stored in a list instead of a map, because of a salted hash
     * scheme that openssh uses. we may not know that an entry is for hostname
     * "george" until someone asks and we check if any of the hashes match.
     */
    private List<Entry> mEntries;

    /**
     * Create a new, empty HostKeys object.
     */
    public HostKeys() {
        mEntries = new ArrayList<Entry>();
    }

    /**
     * Add a host key entry to the table. Any existing entry for a
     * <code>(hostname, keytype)</code> pair will be replaced.
     * 
     * @param hostname
     *            the hostname (or IP) to add
     * @param key
     *            the key to add
     */
    public void add(String hostname, PKey key) {
        for (Iterator<Entry> iter = mEntries.iterator(); iter.hasNext();) {
            Entry e = iter.next();
            if (Arrays.asList(e.mHostnames).contains(hostname)
                    && e.mKey.getSSHName().equals(key.getSSHName())) {
                e.mKey = key;
                return;
            }
        }
        Entry e = new Entry();
        e.mValid = true;
        e.mHostnames = new String[] { hostname };
        e.mKey = key;
        mEntries.add(e);
    }

    /**
     * Read a file of known SSH host keys, in the format used by openssh. On
     * non-Windows platforms, this usually lives in
     * <code>"~/.ssh/known_hosts"</code>.
     * 
     * <p>
     * If this method is called multiple times, the host keys are merged, not
     * cleared. New entries will just replace any overlapping existing entries.
     * 
     * @param in
     *            the stream to read the host keys from
     * @throws IOException
     *             if there's an exception reading or parsing the file
     */
    public void load(InputStream in) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        while (true) {
            String line = reader.readLine();
            if (line == null) {
                break;
            }
            line = Util.strip(line);
            if ((line.length() == 0) || (line.startsWith("#"))) {
                // skip
                continue;
            }

            mEntries.add(Entry.fromLine(line));
        }
    }

    /**
     * Save host keys into a file, in the format used by openssh. The order of
     * keys in the file will be preserved when possible (if these keys were
     * loaded from a file originally).
     * 
     * @param out
     *            the stream to write to
     * @throws IOException
     *             if there's an exception writing to the stream
     */
    public void save(OutputStream out) throws IOException {
        OutputStreamWriter writer = new OutputStreamWriter(out);
        for (Iterator<Entry> iter = mEntries.iterator(); iter.hasNext();) {
            Entry e = iter.next();
            writer.write(e.toLine());
        }
    }

    /**
     * Find hostkey entries for a given hostname or IP. A map of keytype to key
     * is returned. The keytype will be either <code>"ssh-rsa"</code> or
     * <code>"ssh-dss"</code>. If no keys are found for the given host, an empty
     * map is returned.
     * 
     * @param hostname
     *            hostname (or IP) to lookup
     * @return a map of keytype-to-key for the host
     */
    public Map<String, PKey> lookup(String hostname) {
        Map<String, PKey> out = new HashMap<String, PKey>();

        for (Iterator<Entry> iter = mEntries.iterator(); iter.hasNext();) {
            Entry e = iter.next();
            for (int i = 0; i < e.mHostnames.length; i++) {
                if (e.mHostnames[i].equals(hostname)) {
                    out.put(e.mKey.getSSHName(), e.mKey);
                    continue;
                }
                if (e.mHostnames[i].startsWith("|1|")
                        && hashHost(hostname, e.mHostnames[i]).equals(
                                e.mHostnames[i])) {
                    out.put(e.mKey.getSSHName(), e.mKey);
                    continue;
                }
            }
        }
        return out;
    }

    /**
     * Return true if the given key is associated with the given hostname.
     * 
     * @param hostname
     *            hostname (or IP) to lookup
     * @param key
     *            the key to check
     * @return true if the ey is associated with the hostname; false if not
     */
    public boolean check(String hostname, PKey key) {
        PKey hkey = lookup(hostname).get(key.getSSHName());
        if (hkey == null) {
            return false;
        }
        return Util.encodeHex(hkey.toByteArray()).equals(
                Util.encodeHex(key.toByteArray()));
    }

    /**
     * Remove all host keys.
     */
    public void clear() {
        mEntries.clear();
    }

    /**
     * Return the number of entries loaded into this HostKeys object.
     * 
     * @return the number of entries
     */
    public int size() {
        return mEntries.size();
    }

    /**
     * Return a "hashed" form of the hostname, as used by openssh when storing
     * hashed hostnames in the known_hosts file.
     * 
     * @param hostname
     *            the hostname to hash
     * @param salt
     *            (null-ok) optional salt to use when hashing (must be 20 bytes,
     *            base64 encoded)
     * @return the hashed hostname, in <code>"|1|..."</code> format
     */
    public static String hashHost(String hostname, String salt) {
        Crai crai = BaseTransport.getCrai();
        byte[] saltBytes = null;
        if (salt == null) {
            saltBytes = new byte[20];
            crai.getPRNG().getBytes(saltBytes);
        } else {
            if (salt.startsWith("|1|")) {
                salt = Util.splitString(salt, "|")[2];
            }
            saltBytes = Base64.decode(salt);
        }

        if (saltBytes.length != 20) {
            throw new IllegalArgumentException(
                    "Salt must be 20 bytes, base64 encoded");
        }

        CraiDigest hmac = crai.makeSHA1HMAC(saltBytes);
        byte[] hostbytes = hostname.getBytes();
        hmac.update(hostbytes, 0, hostbytes.length);
        byte[] hash = hmac.finish();
        return "|1|" + Base64.encodeBytes(saltBytes) + "|"
                + Base64.encodeBytes(hash);
    }
}
