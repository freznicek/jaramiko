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
 * 
 * 
 * Created on May 8, 2005
 */

package net.lag.paramiko;

/**
 * Interface for controlling the logging done by paramiko.  Java has an
 * embarrassment of riches when it comes to logging packages, and no clear
 * standard, so this interface defines only the simplest logging requirements
 * that paramiko has.
 * 
 * <p>If you use a logging package, you should be able to create a small class
 * that implements these methods by calling into your real logger.  Two simple
 * implementations are provided: {@link ConsoleLog} dumps logs to the java
 * console, and {@link NullLog} absorbs the logs and prevents them from being
 * written anywhere.
 * 
 * @author robey
 */
public interface LogSink
{
    /**
     * An error has occurred which will most likely cause the SSH session to
     * fail.
     * 
     * @param text the log message
     */
    public void error (String text);
    
    /**
     * Something unexpected occurred, but the SSH session should be able to
     * continue.
     * 
     * @param text the log message
     */
    public void warning (String text);
    
    /**
     * Something notable happened in the normal course of events.
     * 
     * @param text the log message
     */
    public void notice (String text);
    
    /**
     * Something normal happened which may be of interest when debugging,
     * but is ordinarily of no interest whatsoever.  Typical applications
     * will only log these messages when in a "debug" mode.
     * 
     * @param text the log message
     */
    public void debug (String text);
    
    /**
     * The hex dump of an actual inbound or outbound packet is being logged.
     * This only happens when {@link Transport#setDumpPackets} is turned on.
     * Only serious debugging sessions will care about, or want to log,
     * these messages.
     * 
     * @param text the log message
     * @param data the packet to dump
     * @param offset offset of the interesting data in the packet
     * @param length length of the interesting data in the packet
     */
    public void dump (String text, byte[] data, int offset, int length);
}
