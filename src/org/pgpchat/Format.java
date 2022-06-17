package org.pgpchat; /** NIS Assignment: Format Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.nio.charset.StandardCharsets;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.Arrays;

/**
 * Format class for each message sent
 */
public interface Format {
    char CA_KEY = 'k';
    char CLIENT_LIST = 'c';
    char EXIT = 'x';
    char FROM = '>';
    char JOIN = 'j';
    char REJECT = 'r';
    char SEP = ':'; 
    char SERVER_EXIT = 'X';

    /**
     * encode a join message
     * @param name
     * @param public key
     * @return message
     */
    static byte[] encodeJoin (String name, PublicKey key)   {
        byte[] publicKey = key.getEncoded();
        byte[] uName = name.getBytes(); 
        byte[] output = new byte[publicKey.length + uName.length + 3]; 
        //format: $j <name length> <name> <key>
        System.arraycopy("$j".getBytes(), 0, output, 0, 2); 
        System.arraycopy(new byte[]{(byte) uName.length}, 0, output, 2, 1);       
        System.arraycopy(uName, 0, output, 3, uName.length);
        System.arraycopy(publicKey, 0, output, 3 + uName.length, publicKey.length);

        return output;  
    }

    /**
     * encode an exit message
     * @param user
     * @return message
     */
    static byte[] encodeExit (String user)  { return ("$x" + user).getBytes(); };

    /**
       * encode a server exit message
       * @param user
       * @return message
       */
    static String encodeServerExit (String user)  { return "$X" + user; };

    /**
     * encode a message
     * @param user
     * @param msg message
     * @return full message
     */
    static byte[] encodeMsg (String user)  { return ("$>" + user + "||").getBytes(); }; 

    /**
     * encode a client list message
     * @param cert certificate
     * @return message
     */
    static byte[] encodeClient(X509Certificate c) throws CertificateEncodingException{
        byte[] cert = c.getEncoded();
        byte[] output = new byte[cert.length + 2];
        System.arraycopy("$c".getBytes(), 0, output, 0, 2);        
        System.arraycopy(cert, 0, output, 2, cert.length);

        return output; 
    }

    /**
     * encode the CA's public key
     * @param k public key
     * @return message
     */
    static byte[] encodeCAPublicKey(PublicKey k){
        byte[] publicKey = k.getEncoded();
        byte[] output = new byte[publicKey.length + 2]; 
        //format: $k <key>
        System.arraycopy("$k".getBytes(), 0, output, 0, 2);
        System.arraycopy(publicKey, 0, output, 2, publicKey.length);

        return output;  
    }

    /**
     * encode rejection message (username already taken)
     * @param name
     * @return message
     */
    static byte[] encodeRejection(String name){return ("$r" + name).getBytes();};
     
    /**
     * strip the head off a control message to get its contents 
     * @param msg
     * @return message
     */
    static String getStringContents (byte[] msg)  { return new String(msg, StandardCharsets.UTF_8).substring(2); }; 
    
    /**
     * gets= contents in byte form
     * @param msg
     * @return message
     */
    static byte[] getByteContents (byte[] msg)  { return Arrays.copyOfRange(msg, 2, msg.length); }; 

    /**
     * obtain the control character of a message
     * @param msg
     * @return control
     */
    static char getControl (String msg)  { return msg.substring(1, 2).charAt(0); }; 
    
    /**
     * obtain the control character of a message
     * @param msg
     * @return control
     */
    static char getControl (byte[] msg)  { return new String(msg, StandardCharsets.UTF_8).substring(1, 2).charAt(0); }; 

    /**
     * obtain the message body from a forwarded text
     * @param msg
     * @return message body
     */
    static String getMsgBody(String msg) {return msg.split(":")[1];};

    /**
     * obtain the user who sent a forwarded messsage
     * @param msg 
     * @return username
     */
    static String getUser (String msg) { return msg.split(":")[0];};

    /**
     * checks if a given message is a control message
     * @param msg
     * @return true if it's a control message
     */    
    static boolean isControl(byte[] msg) { return (new String(msg, StandardCharsets.UTF_8).charAt(0) + "").equals("$"); }; 

    /**
     * checks if the user has requested to exit 
     * @param msg
     * @return true if the user is exiting
     */
    static boolean willExit (String msg) { return (msg.split(" ")[0]).equals("!exit"); }; 
}