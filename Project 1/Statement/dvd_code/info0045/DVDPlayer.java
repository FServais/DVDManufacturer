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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;

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
    public void decryptContent( String encFilename)
    throws PlayerRevokedException, ContentMACException{
        String decFilename = getOutputFilename(encFilename);
        
        try{
            FileInputStream fin = new FileInputStream(encFilename);
            FileOutputStream fout = new FileOutputStream(decFilename);

            
            int inchar;
            while((inchar = fin.read()) != -1)
                fout.write(inchar);
            
            fin.close();
            fout.close();
            
            new File(encFilename).delete();
            
        }catch( Exception e){
            e.printStackTrace();
        }
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
    		Long nodeId = (new BigInteger(Arrays.copyOfRange(rawKeys, i, i+7))).longValue();
    		// 16 last ones are the key
    		byte[] key = Arrays.copyOfRange(rawKeys, i+8, i+23);
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
            
            byte[] rawKeys = player.decryptKeys( playerId, passwd);
            HashMap<Long, byte[]> keys = player.generateKeys(rawKeys);
            for(Long i : keys.keySet()){
            	System.out.println(i);
            	System.out.println(DatatypeConverter.printHexBinary(keys.get(i)));
            }
            player.decryptContent(encFilename);
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
}//end class
