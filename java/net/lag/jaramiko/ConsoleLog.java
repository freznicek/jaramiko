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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple {@link LogSink} implementation which dumps jaramiko's log messages to
 * java's <code>System.err</code>. The log level is indicated with a
 * three-letter abbreviation, and the current time and thread ID is attached,
 * but nothing else fancy is done.
 * 
 * <p>
 * No attempt is made to make the logging efficient or useful. This is only
 * meant for debugging or reference.
 *
 * @deprecated {@link LogSink} has been deprecated in favor of SLF4J
 */
@Deprecated
public class ConsoleLog implements LogSink {
    private static final Logger logger = LoggerFactory
            .getLogger(LogSink.class);

    public void error(String text) {
        logger.error(text);
    }

    public void warning(String text) {
        logger.warn(text);
    }

    public void notice(String text) {
        logger.info(text);
    }

    public void debug(String text) {
        logger.debug(text);
    }

    public void dump(String text, byte[] data, int offset, int length) {
        StringBuffer dump = new StringBuffer();
        for (int i = 0; i < length; i += 16) {
            dump.append("\n");
            dump.append(dumpHex(data, offset + i, length - i));
        }

        logger.info("{} DUMP:{}", text, dump);
    }

    private String dumpHex(byte[] data, int offset, int length) {
        StringBuffer hex = new StringBuffer();
        StringBuffer ascii = new StringBuffer();

        for (int i = 0; i < 16; i++) {
            if (i >= length) {
                hex.append("   ");
                ascii.append(' ');
            } else {
                byte b = data[offset + i];
                String x = Integer.toHexString(b & 0xff).toUpperCase();
                if (x.length() < 2) {
                    hex.append('0');
                }
                hex.append(x);
                hex.append(' ');

                if ((b > 32) && (b < 127)) {
                    ascii.append((char) b);
                } else {
                    ascii.append('.');
                }
            }
        }

        return hex.toString() + "   " + ascii.toString();
    }
}
