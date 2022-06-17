package org.pgpchat; /** NIS Assignment: Compressor Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.io.*;

import java.util.zip.*;

public class Compressor 
    {

        /**
         * Takes a byte array and returns a byte array representation of the compressed array
         * @param message
         * @return compressed
         * @throws IOException
         */
        public static byte[] compress(byte[] message) throws IOException 
        { 
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            GZIPOutputStream gzipOutputStream = new GZIPOutputStream(outputStream);
            gzipOutputStream.write(message); //write the message to the output stream
            gzipOutputStream.close();
            byte[] compressedArray = outputStream.toByteArray();
            //String compressedAsString = new String(compressed);
            //System.out.println("Compressed: " + compressedAsString.substring(0,Math.min(compressedAsString.length(),40)));
            return compressedArray;
        }
     
        /***
         * Takes a compressed byte array and returns a byte array representation of the compressed array
         * @param compressed
         * @return
         * @throws IOException
         */
        public static byte[] decompress(byte[] compressed) throws IOException 
            {
                GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressed));
                byte[] decompressedArray = gzipInputStream.readAllBytes();
            
                return decompressedArray;
            }
        
    }
