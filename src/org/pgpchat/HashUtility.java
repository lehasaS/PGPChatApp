package org.pgpchat; /** NIS Assignment: Hash Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class HashUtility {

    private static final String SHA2_ALGORITHM = "SHA-256"; //Hash algorithm

    /**
     * Create hash
     * @param input input string
     * @return hash
     * @throws Exception Exception
     */
    public static byte[] createSHA2Hash(String input) throws Exception{
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byteStream.write(input.getBytes());
        byte[] valueToHash = byteStream.toByteArray();

        MessageDigest messageDigest = MessageDigest.getInstance(SHA2_ALGORITHM);
        return messageDigest.digest(valueToHash);
    }

    /**
     * Create hash
     * @param signature Signature
     * @param calculated Calculated hash
     * @return true or false
     */
    public static boolean compareHash(byte[] signature, byte[] calculated){
        return Arrays.equals(signature,calculated);
    }
}
