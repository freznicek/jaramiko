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

import java.util.List;

/**
 * Simple interface for a factory to create Channels.  You only need to use
 * this if you are creating custom channel types that need special features
 * like ChannelRequests -- in other words, implementing new protocols over
 * SSH.  Use {@link Transport#registerChannelKind} to register the factory
 * with your Transport.
 *
 * @author msullivan
 */
public interface ChannelFactory
{
    /**
     * Create a channel from parameters that are in the form of a list.  This
     * is called from {@link ClientTransport} when a client channel is opened.
     * 
     * @param kind arbitrary string (defined by the argument to
     *     {@link ClientTransport#openChannel) indicating the kind of channel
     *     to open
     * @param chanid the transport-defined ID for the channel
     * @param params any parameters that were passed from openChannel.
     * @return an appropriate Channel object.
     */
    public Channel createChannel(String kind, int chanid, List params);
           
    /**
     * Create a channel from parameteres that are in the form of an SSH
     * {@link Message}.  This is called from {@link ServerTransport} when the
     * remote client has requested a special channel type.  The parameters
     * (if any) can be retrieved from the Message object.
     * 
     * @param kind arbitrary string (defined by the argument to
     *     {@link ClientTransport#openChannel) string indicating the kind of
     *     channel to open
     * @param chanid the transport-defined ID for the channel
     * @param params parameters that were originally passed by the remote
     *     client as a List.
     * @return an appropriate Channel object
     */
    public Channel createChannel(String kind, int chanid, Message params);
}
