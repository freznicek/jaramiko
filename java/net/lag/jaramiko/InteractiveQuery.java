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


/**
 * Information from the server to the client containing instructions and
 * prompts for an interactive authentication request.
 * 
 * @author robey
 */
public class InteractiveQuery
{
    /**
     * An interactive authentication prompt from the server.  Each prompt
     * contains the prompt {@link #text} and a boolean ({@link #echoResponse})
     * indicating if the response should be echoed back.
     */
    public static class Prompt
    {
        /** The prompt to offer the user */
        public String text;
        
        /** Indicates if the user's response should be echoed back (ie, is not a password) */
        public boolean echoResponse;
    };

    
    /**
     * A short title for the dialog or session.
     */
    public String title;
    
    /**
     * Longer-form instructions from the server, suitable for displaying inside
     * a dialog box (for example).
     */
    public String instructions;
    
    /**
     * An array of prompts (text + echo indicator) to ask the user.
     */
    public Prompt[] prompts;
}
