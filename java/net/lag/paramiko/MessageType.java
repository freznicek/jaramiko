/*
 * Created on May 8, 2005
 */

package net.lag.paramiko;

/**
 * Constants used by paramiko for SSH2 packet types.
 * 
 * @author robey
 */
/* package */ class MessageType
{
    public static final int DISCONNECT = 1;
    public static final int IGNORE = 2;
    public static final int UNIMPLEMENTED = 3;
    public static final int DEBUG = 4;
    public static final int SERVICE_REQUEST = 5;
    public static final int SERVICE_ACCEPT = 6;
    
    public static final int KEX_INIT = 20;
    public static final int NEW_KEYS = 21;
    
    public static final int KEX_0 = 30;
    public static final int KEX_1 = 31;
    public static final int KEX_2 = 32;
    public static final int KEX_3 = 33;
    public static final int KEX_4 = 34;

    public static final int USERAUTH_REQUEST = 50;
    public static final int USERAUTH_FAILURE = 51;
    public static final int USERAUTH_SUCCESS = 52;
    public static final int USERAUTH_BANNER = 53;
    
    public static final int USERAUTH_PK_OK = 60;
    
    public static final int GLOBAL_REQUEST = 80;
    public static final int REQUEST_SUCCESS = 81;
    public static final int REQUEST_FAILURE = 82;

    public static final int CHANNEL_OPEN = 90;
    public static final int CHANNEL_OPEN_SUCCESS = 91;
    public static final int CHANNEL_OPEN_FAILURE = 92;
    public static final int CHANNEL_WINDOW_ADJUST = 93;
    public static final int CHANNEL_DATA = 94;
    public static final int CHANNEL_EXTENDED_DATA = 95;
    public static final int CHANNEL_EOF = 96;
    public static final int CHANNEL_CLOSE = 97;
    public static final int CHANNEL_REQUEST = 98;
    public static final int CHANNEL_SUCCESS = 99;
    public static final int CHANNEL_FAILURE = 100;
    
    
    public static String
    getDescription (int t)
    {
        switch (t) {
        case DISCONNECT:
            return "disconnect";
        case IGNORE:
            return "ignore";
        case UNIMPLEMENTED:
            return "unimplemented";
        case DEBUG:
            return "debug";
        case SERVICE_REQUEST:
            return "service-request";
        case SERVICE_ACCEPT:
            return "service-accept";
        case KEX_INIT:
            return "kex-init";
        case NEW_KEYS:
            return "new-keys";
        case KEX_0:
            return "kex0";
        case KEX_1:
            return "kex1";
        case KEX_2:
            return "kex2";
        case KEX_3:
            return "kex3";
        case KEX_4:
            return "kex4";
        case USERAUTH_REQUEST:
            return "userauth-request";
        case USERAUTH_FAILURE:
            return "userauth-failure";
        case USERAUTH_SUCCESS:
            return "userauth-success";
        case USERAUTH_BANNER:
            return "userauth-banner";
        case USERAUTH_PK_OK:
            return "userauth-pk-ok";
        case GLOBAL_REQUEST:
            return "global-request";
        case REQUEST_SUCCESS:
            return "request-success";
        case REQUEST_FAILURE:
            return "request-failure";
        case CHANNEL_OPEN:
            return "channel-open";
        case CHANNEL_OPEN_SUCCESS:
            return "channel-open-success";
        case CHANNEL_OPEN_FAILURE:
            return "channel-open-failure";
        case CHANNEL_WINDOW_ADJUST:
            return "channel-window-adjust";
        case CHANNEL_DATA:
            return "channel-data";
        case CHANNEL_EXTENDED_DATA:
            return "channel-extended-data";
        case CHANNEL_EOF:
            return "channel-eof";
        case CHANNEL_CLOSE:
            return "channel-close";
        case CHANNEL_REQUEST:
            return "channel-request";
        case CHANNEL_SUCCESS:
            return "channel-success";
        case CHANNEL_FAILURE:
            return "channel-failure";
        default:
            return "$" + Integer.toString(t);
        }
    }

}