/*
 * INFO0045: Assignment 1
 *
 * Encrypts a given content file with a set of guaranteed not to include any
 * player's keys in the revocation list, but which will allow any other player to
 * properly decrypt the content.
 */

package info0045;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.lang.StringBuilder;
import java.nio.ByteBuffer;

public class DVDManufacturer{
    /*
     * Attributes
     */
    private final static String revocationFilename = "revoke.lst";
    
    
    /*
     * Constructor
     */
    public DVDManufacturer(){
        
    }
    
    
    /*
     * Public methods
     */
    
    // ----------------------- CLASS ----------------------- //
    
    // Parse the command line and encrypt the given content
    // Usage: DVDManufacturer <AACS Pwd> <content title> <content file>
    public static void main( String[] args ){
        
        try{
            if(args.length != 3){
                System.out.println("Usage: DVDManufacturer <AACS Pwd> <content title> <content filename>");
                return;
            }
            
            String aacsPwd = args[0];
            String title = args[1];
            String contentFile = args[2];
            
            long[] revList = parseRevocationFile();

            DVDManufacturer manu = new DVDManufacturer();
            
            manu.encryptContent(title, contentFile, revList, aacsPwd);
            
        }catch(Exception e){
            e.printStackTrace();
        }
    }//end main()
    
    
    // ----------------------- INSTANCE ----------------------- //
    
    // Encrypts the content. You need to implement this function:
    // right now it just copies the input content file to an output
    // file and deletes the original content file. Your output file
    // should be named by a call to getOutputFilename.
    
    /**
     * Method that encrypt the content of a file ('contentFilename'), with a title 'title' 
     * such that the player's id in 'revocationList' can not decrypt it.
     * It is also using a password 'aacsPasswd' to retreive the keys corresponding to the nodes
     * with which the file will be encrypted (AACS Master key).
     * The encrypted content will be stored in the file "'contentFilename'.enc".
     * 
     * @param title           Title of the file
     * @param contentFilename Path of the file to encrypt.
     * @param revocationList  List of id's of the players that won't be able to decrypt.
     * @param aacsPasswd      Password for the AACS master key.
     */
    public void encryptContent( String title, String contentFilename,
                               long [] revocationList, String aacsPasswd){
        
        String encFilename = getOutputFilename(contentFilename);
        
        try{
            FileInputStream fin = new FileInputStream(contentFilename);
            FileOutputStream fout = new FileOutputStream(encFilename);
            
            // Reading
            StringBuilder sb = new StringBuilder();
            int inchar;
            while((inchar = fin.read()) != -1){
                sb.append((char)inchar);
            }

            String content = sb.toString();
            
            // Cover set
            long[] idsCover = new KeyTree().getCoverSet(revocationList);
            
            // Encryption
            byte[] encryptedContent = encrypt(title, content, idsCover, aacsPasswd);            
            
            // Writing
            fout.write(encryptedContent);
            
            fin.close();
            fout.close();
            
            new File(contentFilename).delete();
            
        }catch( Exception e ){
            e.printStackTrace();
        }
    }//end encryptContent()
    
    
    
    /*
     * Private methods
     */
    
    // ----------------------- CLASS ----------------------- //
    
    // Parses the revocation file, assumed to be at revoke.lst
    // The format is just text integer player ids separated by newlines
    /**
     * Parses the revocation file, assumed to be at revoke.lst.
     * The format is just text integer player ids separated by newlines
     * @return Array of player's id's which are revoked.
     */
    private static long[] parseRevocationFile(){
        try{
            ArrayList<Long> revoked = new ArrayList<Long>();
            
            BufferedReader fin = new BufferedReader(new FileReader(revocationFilename));
            String str;
            
            while((str = fin.readLine()) != null){
                revoked.add( Long.parseLong(str));
            }//end while
            
            fin.close();
            
            long []revList = new long[revoked.size()];
            for(int i = 0; i < revList.length; ++i)
                revList[i] = revoked.get(i);
            
            return revList;
        }catch(IOException e){
            return new long[0];
        }
    }//end parseRevocation()
    
    private static String getOutputFilename(String filename){
        return filename + ".enc";
    }//end getOutputFileName();

    
    
    // ----------------------- INSTANCE ----------------------- //
    
    /**
     * Function that encrypt a content using a set of keys, given by an array of id's and a AACS Master password.
     * 
     * Format : 
     * - HEADER
     *  - Size of the title (4 bytes)
     *  - Title
     *  - Number of nodes (4 bytes)
     *  - Number of bytes needed for a node id (on 1 byte)
     *  - Number of bytes needed for a key (on 1 byte)
     *  - Node || Key
     *  - Size (in bytes) of the initialization vector (on 1 byte)
     *  - IV
     *  - Size (in bytes) of the content (on 4 bytes)
     * - CONTENT
     *  - Content
     * - MAC
     *  - Mac (64 bytes)
     * 
     * @param content_title Title of the content.
     * @param content       Content to encrypt.
     * @param coverIds      Id's of the node able to decrypt.
     * @param aacsPasswd    AACS Master password.
     * 
     * @return Encrypted version of the content.
     */
    private byte[] encrypt(String content_title, String content, long[] coverIds, String aacsPasswd){
    	ArrayList<Byte> encryption = new ArrayList<Byte>();
    	
        try {
            /* 
             * ==========================================
             *           Generation of K_t
             * ==========================================
             */
            KeyGenerator kg = null;
            kg = KeyGenerator.getInstance("HmacSHA256");
    
            SecretKey kt = kg.generateKey();
            byte[] ktBytes = kt.getEncoded(); 

            
            /* 
             * ==========================================
             *        Generation of K_enc & K_mac
             * ==========================================
             */
            byte[] kEnc = deriveKeyEnc(ktBytes);
            SecretKey kEncSpec = new SecretKeySpec(kEnc, "AES");
            
            byte[] kMac = deriveKeyMac(ktBytes);
            
            
            /* 
             * ==========================================
             *          Encryption of the content
             * ==========================================
             */
            
            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, kEncSpec);
            
            byte[] IV = cipher.getIV();
            
            byte[] encryptedBytes = cipher.doFinal(content.getBytes());
            
            
            /* 
             * ==========================================
             *          Translate nodes to keys
             * ==========================================
             */
            
            PlayerKeys pk = new PlayerKeys();
            HashMap<Long, byte[]> setKeys = new HashMap<Long, byte[]>();
            
            for(long id : coverIds)
                setKeys.put(id, pk.generateKey(id, KeyTree.createAESKeyMaterial(aacsPasswd)));
            
            
            /* 
             * ==========================================
             *      Encrypt K_t with set of keys
             * ==========================================
             */
            
            HashMap<Long, byte[]> encryptionsKt = new HashMap<Long, byte[]>();
            
            Iterator<Map.Entry<Long, byte[]>> it = setKeys.entrySet().iterator();
            
            Cipher keyCipher = Cipher.getInstance("AES");
            while(it.hasNext()){
                Map.Entry<Long, byte[]> pair = it.next();
                keyCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(pair.getValue(), "AES"));
                encryptionsKt.put(pair.getKey(), keyCipher.doFinal(ktBytes));
               }
            
            
            /* 
             * ==========================================
             *             Generate the file 
             * ==========================================
             */
            
            int titleSize = content_title.length();
            int numOfKeys = setKeys.size();
            byte nodeSize = 8; // Node in a long -> 8 bytes
            byte keySize = (byte) encryptionsKt.entrySet().iterator().next().getValue().length;
            byte ivSize = (byte) IV.length;
            int contentSize = encryptedBytes.length;
            
            addArrayToListByte(encryption, intToBytes(titleSize));
            addArrayToListByte(encryption, content_title.getBytes());
            addArrayToListByte(encryption, intToBytes(numOfKeys));
            encryption.add(nodeSize);
            encryption.add(keySize);
            
            Iterator<Map.Entry<Long, byte[]>> it_bytes = encryptionsKt.entrySet().iterator();
            while(it_bytes.hasNext()){
                Map.Entry<Long, byte[]> pair = it_bytes.next();
                // node||key
                addArrayToListByte(encryption, longToBytes(pair.getKey())); 
                addArrayToListByte(encryption, pair.getValue());
                
                //System.out.println("<Key ; Value> : <" + pair.getKey() + " ; <" + DatatypeConverter.printHexBinary(pair.getValue()) + ">");
            }
            
            encryption.add(ivSize);
            addArrayToListByte(encryption, IV); // Initialization vector
            
            addArrayToListByte(encryption, intToBytes(contentSize));
            addArrayToListByte(encryption, encryptedBytes); //Content
            
            
            /* 
             * ==========================================
             *                Generate MAC
             * ==========================================
             */

            byte[] macFile = generateMAC(listToArrayBytes(encryption), kMac);
            addArrayToListByte(encryption, macFile);
            
            return listToArrayBytes(encryption);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    
    // ----------------------- INSTANCE ----------------------- //
    
    /**
     * Derive K_Enc from K_t (see statement).
     * @param kt K_t.
     * @return K_Enc.
     */
    private byte[] deriveKeyEnc(byte[] kt){
        SecretKeySpec ktSpec = new SecretKeySpec(kt, "HmacMD5");
        
        Mac mac;
        try {
            mac = Mac.getInstance("HmacMD5");
            mac.init(ktSpec);

            return mac.doFinal("enc".getBytes()); // K_enc = HMAC(K_t, "enc")
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }    
    }
    
    /**
     * Derive K_Mac from K_t (see statement).
     * @param kt K_t.
     * @return K_Mac.
     */
    private byte[] deriveKeyMac(byte[] kt){
        SecretKeySpec ktSpec = new SecretKeySpec(kt, "HmacSHA1");
        
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(ktSpec);

            return mac.doFinal("mac".getBytes()); // K_mac = HMAC(K_t, "mac")
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }   
    }
    
    
    /**
     * Compute the hash of 'content'. The HMAC512 is computed, with the key 'K_mac'.
     * @param content Content to hash.
     * @param kMac    Key to hash.
     * @return MAC of content.
     */
    private byte[] generateMAC(byte[] content, byte[] kMac){
        SecretKeySpec ktSpec = new SecretKeySpec(kMac, "HmacSHA512");
        
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA512");
            mac.init(ktSpec);

            return mac.doFinal(content);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    
    /**
     * Add items of an array of byte to a ArrayList of Byte.
     * @param list  ArrayList of Byte (receiver).
     * @param array Array of byte.
     */
    private void addArrayToListByte(ArrayList<Byte> list, byte[] array){
    	for(byte item : array)
    		list.add(item);
    }
    
    /**
     * Convert a long to an array of 8 bytes.
     * @param x Long to convert.
     * @return Array of 8 bytes (that form x).
     */
    private byte[] longToBytes(long x){
    	return ByteBuffer.allocate(8).putLong(x).array();
    }
    
    
    /**
     * Convert a int to an array of 4 bytes.
     * @param x Int to convert.
     * @return Array of 4 bytes (that form x).
     */
    private byte[] intToBytes(int x){
    	return ByteBuffer.allocate(4).putInt(x).array();
    }
    
    
    /**
     * Convert a list a Byte to an array containing the same items.
     * @param list List to convert.
     * @return Array containing the elements in the list.
     */
    private byte[] listToArrayBytes(ArrayList<Byte> list){
    	byte[] bytes = new byte[list.size()];
    	int i = 0;
    	for(Byte b : list){
    		bytes[i] = (byte)b;
    		++i;
    	}
    	
    	return bytes;
    }
    
}//end class
