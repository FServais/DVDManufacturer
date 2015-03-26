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
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
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
    
    public HashMap<Long, byte[]> generateKeys( byte[] rawKeys) {
    	
    	HashMap<Long, byte[]> keys = new HashMap<>();
    	
    	for(int i = 0; i+24 < rawKeys.length ; i+=24){
    		Long nodeId = (new BigInteger(Arrays.copyOfRange(rawKeys, i, i+8))).longValue();
    		byte[] key = Arrays.copyOfRange(rawKeys, i+8, i+24);
    		keys.put(nodeId, key);
    	}
    	return keys;
    }
    

    public byte[] decryptKeys( long playerId, String passwd) throws FileNotFoundException, ContentMACException{
		
    	File file = new File(DVDPlayer.getKeyFilename(playerId));
        FileInputStream fileRead = new FileInputStream(file);
        byte[] fileContent = new byte[((int)file.length()) - 20];
        byte[] mac = new byte[20];
       
        try {
        
        fileRead.read(fileContent);	
        fileRead.read(mac);	
        
        byte[] pass = KeyTree.createAESKeyMaterial(passwd); 
        Key sec = new SecretKeySpec(pass, "AES");

        
		Cipher AesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        AesCipher.init(Cipher.DECRYPT_MODE, sec);
        byte[] bytePlainText = AesCipher.doFinal(fileContent);
    	
        Mac macCheck = Mac.getInstance("HmacSHA1");
		SecretKeySpec secret = new SecretKeySpec(passwd.getBytes(), macCheck.getAlgorithm());
		macCheck.init(secret);
		byte[] auth = macCheck.doFinal(fileContent);
		
		if(!Arrays.equals(mac, auth)) 
			throw new ContentMACException();
    	
		return bytePlainText;
    	
        } catch (IOException | NoSuchAlgorithmException| IllegalBlockSizeException | NoSuchPaddingException 
        		| BadPaddingException | InvalidKeyException e) {
			// TODO Auto-generated catch block
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
                Reading the file with the keys
             */

            byte[] rawKeys = player.decryptKeys( playerId, passwd);

            HashMap<Long, byte[]> keys = player.generateKeys(rawKeys);
            //player.decryptContent(encFilename);


            /*
                Reading the DVD
             */
            
            BufferedReader br = new BufferedReader(new FileReader(encFilename));
            StringBuilder file = new StringBuilder();
            String title = br.readLine();
            file.append(title + "\n");
            
            String line;
            HashMap<Long, String> nodesKeys = new HashMap<Long, String>();
            
            int end_line = 0;
            String[] id_key;
            while((line = br.readLine()) != null && (id_key = line.split(" ")).length > 1){
                nodesKeys.put(Long.parseLong(id_key[0]), id_key[1]);
                file.append(line + "\n");
            }
            
            String iv = line;
            String content = br.readLine();
            String mac = br.readLine();
            
            if(iv == null || content == null || mac == null){
                System.err.println("Malformed file.");
                return;
            }
            
            file.append(iv + "\n");
            file.append(content + "\n");
            
            System.out.println("Title : " + title);
            Iterator<Map.Entry<Long, String>> it = nodesKeys.entrySet().iterator();
            while(it.hasNext()){
                Map.Entry<Long, String> pair = (Map.Entry<Long, String>) it.next();
            }


            Iterator<Map.Entry<Long, byte[]>> it_keys_file = keys.entrySet().iterator();
            while(it_keys_file.hasNext()){
                Map.Entry<Long, byte[]> pair = (Map.Entry<Long, byte[]>) it_keys_file.next();
                long nodeID = pair.getKey();
                byte[] key = pair.getValue();
                
                if(!nodesKeys.containsKey(nodeID))
                    continue;
                
                
                byte[] keyFile = DatatypeConverter.parseHexBinary(nodesKeys.get(nodeID));
                
                Cipher keyCipher = Cipher.getInstance("AES");
                keyCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                byte[] plain_kt = keyCipher.doFinal(keyFile);
                
                byte[] k_mac = deriveKeyMac(plain_kt);
                
                byte[] mac_content = generateMAC(file.toString(), k_mac);
                
                // Check the MAC
                if(!mac.equals(DatatypeConverter.printHexBinary(mac_content))){
                    System.err.println("MAC not corresponding");
                    return;
                }
                
                
                // Derive k_enc
                byte[] k_enc = deriveKeyEnc(plain_kt);
                
                // Decrypt
                SecretKey kEncSpec = new SecretKeySpec(k_enc, "AES");
                Cipher cipher = null;
                cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, kEncSpec, new IvParameterSpec(DatatypeConverter.parseHexBinary(iv)));
                
                byte[] plain_content = cipher.doFinal(DatatypeConverter.parseHexBinary(content));
                
                System.out.println("============== Plain text ============== ");
                System.out.println(new String(plain_content, "UTF-8"));
                System.out.println("======================================== ");

                break;
            }

        /*
        }catch(PlayerRevokedException e){
            System.err.println("Unable to decrypt content: Player revoked");
        */
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
        
        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE);
        buffer.putLong(x);
        return buffer.array();
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
    
    private static byte[] generateMAC(String content, byte[] kMac){
        SecretKeySpec ktSpec = new SecretKeySpec(kMac, "HmacSHA512");
        
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA512");
            mac.init(ktSpec);

            return mac.doFinal(content.getBytes());
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
