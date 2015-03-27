/*
 * INFO0045: Assignment 1
 *
 * Should decrypt the encrytped file given or indicate one of two posible failures:
 * 1) player revocation
 * 2) content file MAC failure
 */

package info0045;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import java.nio.ByteBuffer;
<<<<<<< HEAD
=======

>>>>>>> origin/Fabs
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
<<<<<<< HEAD
import java.util.Arrays;
import java.util.HashMap;
import java.security.MessageDigest;
import java.util.*;
=======
import java.security.MessageDigest;

import java.util.*;
import java.util.Arrays;
import java.util.HashMap;
>>>>>>> origin/Fabs

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class DVDPlayer {
    
    // Creates a new DVDPlayer object.
    public DVDPlayer(long playerId, String passwd){
        
    }//end constructor
    
    // Verifys and attempts to decrypt the content in encFilename.
    // You need to implement this function: right now it just copies
    // to "encrypted" file to the output file and deletes the "encrypted"
    // file. You should name the output file by calling
    // getOutputFilename(encFilename). If there is a failure
    // e.g. the player is revoked, you should throw PlayerRevokedException
    // or ContentMACException, as appropriate.
    public void decryptContent( String encFilename, HashMap<Long, byte[]> keys )
    throws PlayerRevokedException, ContentMACException{
        String decFilename = getOutputFilename(encFilename);
        boolean nodeFound = false;
        
        
        try{
            FileInputStream fin = new FileInputStream(encFilename);
            FileOutputStream fout = new FileOutputStream(decFilename);
            
            /* 
             * ==========================================
             *       		Reading the DVD
             * ==========================================
             */
            
            byte[] titleSize_arr = new byte[4];
            int titleSize;

            byte[] numOfKeys_arr = new byte[4];
            int numOfKeys;

            byte[] nodeSize_arr = new byte[1];
            byte nodeSize;

            byte[] keySize_arr = new byte[1];
            byte keySize;

            byte[] ivSize_arr = new byte[1];
            byte ivSize;

            byte[] contentSize_arr = new byte[4];
            int contentSize;
            
            
            fin.read(titleSize_arr);
            titleSize = bytesToInt(titleSize_arr);
            
            byte[] title_arr = new byte[titleSize];
            fin.read(title_arr);
            String title = new String(title_arr, "UTF-8");
            
            fin.read(numOfKeys_arr);
            numOfKeys = bytesToInt(numOfKeys_arr);
            
            fin.read(nodeSize_arr);
            nodeSize = nodeSize_arr[0];
            
            fin.read(keySize_arr);
            keySize = keySize_arr[0];
            
            HashMap<Long, byte[]> nodesKeys = new HashMap<Long, byte[]>();
            
            for(int i = 0 ; i < numOfKeys ; ++i){
            	byte[] node_arr = new byte[nodeSize];
            	byte[] key = new byte[keySize];
            	
            	fin.read(node_arr);
            	fin.read(key);

            	nodesKeys.put(bytesToLong(node_arr), key);
            }
            
            fin.read(ivSize_arr);
            ivSize = ivSize_arr[0];
            byte[] iv = new byte[ivSize];
            fin.read(iv);
            
            fin.read(contentSize_arr);
            contentSize = bytesToInt(contentSize_arr);
            
            byte[] content = new byte[contentSize];
            fin.read(content);
            
            byte[] mac = new byte[64];
            fin.read(mac);
                        
            fin.close();
            
            fin = new FileInputStream(encFilename);
            byte[] fileWithoutMac = new byte[4 + titleSize + 4 + 1 + 1 + (nodeSize + keySize) * numOfKeys + 1 + ivSize + 4 + contentSize];
            fin.read(fileWithoutMac);
            
            fin.close();
        
            /* 
             * ==========================================
             *       		Decryption
             * ==========================================
             */
            
            Iterator<Map.Entry<Long, byte[]>> it_keys_file = keys.entrySet().iterator();
            while(it_keys_file.hasNext()){
                Map.Entry<Long, byte[]> pair = (Map.Entry<Long, byte[]>) it_keys_file.next();
                long nodeID = pair.getKey();
                byte[] key = pair.getValue();
                                
                if(!nodesKeys.containsKey(nodeID))
                    continue;
                
                nodeFound = true;
                
                byte[] keyFile = nodesKeys.get(nodeID);
                
                Cipher keyCipher = Cipher.getInstance("AES");
                keyCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                byte[] plain_kt = keyCipher.doFinal(keyFile);
                                
                byte[] k_mac = deriveKeyMac(plain_kt);
                                
                byte[] mac_content = generateMAC(fileWithoutMac, k_mac);
                
                // Check the MAC
                if(!DatatypeConverter.printHexBinary(mac).equals(DatatypeConverter.printHexBinary(mac_content)))
                    throw new ContentMACException();
                
                
                // Derive k_enc
                byte[] k_enc = deriveKeyEnc(plain_kt);
                
                // Decrypt
                SecretKeySpec kEncSpec = new SecretKeySpec(k_enc, "AES");
                Cipher cipher = null;
                cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, kEncSpec, new IvParameterSpec(iv));
                
                byte[] plain_content = cipher.doFinal(content);
                
                fout.write(title.getBytes());
                fout.write("\n".getBytes());
                fout.write(plain_content);
                
                break;
            }

            fout.close();
            
        }catch( Exception e){
            e.printStackTrace();
        }
        
        if(!nodeFound)
        	throw new PlayerRevokedException();
        
        new File(encFilename).delete();
        
    }//end decryptContent()
    
    /**
     * generateKeys : the keys and the node ids are concatened in a byte array.
     *  This method extract it and put it in a HashMap
     * @param rawKeys : the byte array representing the keys informations
     * @return an HashMap where each key is a node id and the value is the corresponding key.
     */
    public HashMap<Long, byte[]> generateKeys( byte[] rawKeys) {
    	
    	HashMap<Long, byte[]> keys = new HashMap<>();
    	
    	for(int i = 0; i+24 < rawKeys.length ; i+=24){
    		// 8 first bytes are the node Id
    		Long nodeId = (new BigInteger(Arrays.copyOfRange(rawKeys, i, i+8))).longValue();
    		// 16 last ones are the key
    		byte[] key = Arrays.copyOfRange(rawKeys, i+8, i+24);
    		keys.put(nodeId, key);
    	}
    	return keys;
    }
    
    /**
     * decryptKeys : given the encrypted keyfile, extracts the plain text corresponding to the keys
     * @param playerId player number
     * @param passwd player password
     * @return byte array of keys
     * @throws FileNotFoundException in case of absence of keyfile
     * @throws ContentMACException in case of unmatching MACss
     */
    public byte[] decryptKeys( long playerId, String passwd) throws FileNotFoundException, ContentMACException{
		
    	File file = new File(DVDPlayer.getKeyFilename(playerId));
        FileInputStream fileRead = new FileInputStream(file);
        byte[] fileContent = new byte[((int)file.length()) - 64];
        byte[] mac = new byte[32];
        byte[] cipherIV = new byte[32];
       
        try {
        	
        // retrieve info
        fileRead.read(cipherIV);	
        fileRead.read(fileContent);	
        fileRead.read(mac);	
        

        // Check mac value
        Mac macCheck = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret = new SecretKeySpec(passwd.getBytes(), macCheck.getAlgorithm());
		macCheck.init(secret);
		byte[] auth = macCheck.doFinal(fileContent);
		
		// if the mac don't match, the file has been modified
		if(!Arrays.equals(mac, auth)) 
			throw new ContentMACException();
		
        // generate the key for decryption
        byte[] pass = KeyTree.createAESKeyMaterial(passwd); 
        Key sec = new SecretKeySpec(pass, "AES");
        
        // decrypt IV
        Cipher AesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        AesCipher.init(Cipher.DECRYPT_MODE, sec);
        byte[] iv =  AesCipher.doFinal(cipherIV);
       
        // With IV, decrypt keys
        IvParameterSpec ivSpec = new IvParameterSpec(iv); 
		AesCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        AesCipher.init(Cipher.DECRYPT_MODE, sec, ivSpec);
        byte[] bytePlainText = AesCipher.doFinal(fileContent);
    	
		return bytePlainText;
    	
        } catch (IOException | NoSuchAlgorithmException| IllegalBlockSizeException | NoSuchPaddingException 
        		| BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {

			e.printStackTrace();
		} 
    	return null;

    }
    
    
    // Parse the command line and decrypt the data.
    // Usage: DVDPlayer <player id> <player keyfile passwd> <encrypted file>
    public static void main(String[] args){
        try{
            if(args.length != 3){
                System.out.println("Usage: DVDPlayer <playerID> <player keyfile passwd> <encrypted file>");
                return;
            }
            
            long playerId = Integer.parseInt(args[0]);
            String passwd = args[1];
            String encFilename = args[2];
            
            DVDPlayer player = new DVDPlayer(playerId, passwd);

            /* 
             * ==========================================
             *       Reading the file with the keys
             * ==========================================
             */

            byte[] rawKeys = player.decryptKeys( playerId, passwd);
            HashMap<Long, byte[]> keys = player.generateKeys(rawKeys);


            player.decryptContent(encFilename, keys);
        }catch(PlayerRevokedException e){
            System.err.println("Unable to decrypt content: Player revoked");
        }catch( ContentMACException e){
            System.err.println("Unable to decrypt content: MAC Failure");
        }catch( Exception e){
            e.printStackTrace();
        }
    }//end main()
    
    class PlayerRevokedException extends Exception{
    
    }//end inner class
    
    class ContentMACException extends Exception{
    
    }//end inner class
    
    // generates a canonical filename for the keyfile of each DVD player
    public static String getKeyFilename(long playerId){
        String filename = "player_" + Long.toString(playerId) + ".key";
        
        return filename;
    }//end getKeyFilename()
    
    // Assumes the filename ends in .enc and just drops those last
    // 4 characters.
    private static String getOutputFilename(String encFilename){
        return encFilename.substring(0, encFilename.length()-4);
    }//end getOutputFilename

    protected byte[] generateKey(long nodeId, byte[] aacsKey){
        
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] nodeIdToByte = longToBytes(nodeId);
        
        byte[] toReturn = new byte[nodeIdToByte.length];
        for(int i = 0; i < nodeIdToByte.length && i < aacsKey.length; ++i)          
            toReturn[i] = (byte) (nodeIdToByte[i] ^ aacsKey[i]); 
        
        return md.digest(toReturn);
        
    }
    
    
    public byte[] longToBytes(long x) {
        
    	return ByteBuffer.allocate(8).putLong(x).array();
    }
    
    private long bytesToLong(byte[] buf){
    	long l = ((buf[0] & 0xFFL) << 56) |
    	         ((buf[1] & 0xFFL) << 48) |
    	         ((buf[2] & 0xFFL) << 40) |
    	         ((buf[3] & 0xFFL) << 32) |
    	         ((buf[4] & 0xFFL) << 24) |
    	         ((buf[5] & 0xFFL) << 16) |
    	         ((buf[6] & 0xFFL) <<  8) |
    	         ((buf[7] & 0xFFL) <<  0) ;
    	return l;
	}
    
    // http://stackoverflow.com/a/5399829
    private int bytesToInt(byte[] b){
    	return   b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
	}
    
    
    protected byte[] generateKey(long nodeId, String aacsPasswd){
        try {
            return generateKey(nodeId, KeyTree.createAESKeyMaterial(aacsPasswd));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    private static byte[] deriveKeyMac(byte[] kt){
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
    
    private static byte[] deriveKeyEnc(byte[] kt){
        SecretKeySpec ktSpec = new SecretKeySpec(kt, "HmacSHA1");
        
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
 

}//end class
