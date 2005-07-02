/*
 * opyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
 *
 * Paramiko is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Paramiko; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
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
