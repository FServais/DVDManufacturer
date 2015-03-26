/*
 * INFO0045: Assignment 1
 *
 * Given a player ID, generates a set of keys for that player and write it
 * to a file
 */

package info0045;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class PlayerKeys{

	protected byte[] generateKey(long nodeId, String aacsPasswd){
        try {
            return this.generateKey(nodeId, KeyTree.createAESKeyMaterial(aacsPasswd));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

	protected byte[] generateKey(long nodeId, byte[] aacsKey){
		
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] nodeIdToByte = longToBytes(nodeId);
		
		byte[] toReturn = new byte[nodeIdToByte.length];
		for(int i = 0; i < nodeIdToByte.length && i < aacsKey.length; ++i)			
			toReturn[i] = (byte) (nodeIdToByte[i] ^ aacsKey[i]); 
		byte[] key = md.digest(toReturn);
		return key;
		
	}
	
	public byte[] concat(byte[] a, byte[] b) {
		
		   int aLen = a.length;
		   int bLen = b.length;
		   byte[] c= new byte[aLen+bLen];

		   System.arraycopy(a, 0, c, 0, aLen);
		   System.arraycopy(b, 0, c, aLen, bLen);
		   
		   return c;
		}
    
	public byte[] longToBytes(long x) {
		
	    ByteBuffer buffer = ByteBuffer.allocate(8);
	    buffer.putLong(x);
	    return buffer.array();
	}
	
    // Should write the encrypted keyfile to the filename specified
    // by DVDPlayer.getKeyFilename(playerId). Now it only writes
    // the node Ids in plaintext to the file. You need to generate
    // the keys associated with the node IDs and store them in the file
    // encrypted.
    public void writeKeys(long playerId, String aacsPasswd, String passwd){
        KeyTree keyTree = new KeyTree();
        
        // get the associated nodes
        long[] nodeIds = keyTree.getPathNodes(playerId);
        
        try{
        	
            String keyFilename = DVDPlayer.getKeyFilename(playerId);
            //BufferedWriter fout = new BufferedWriter(new FileWriter(keyFilename));
            FileOutputStream fout = new FileOutputStream(keyFilename);
            byte[] aacsKey = KeyTree.createAESKeyMaterial(aacsPasswd);
            
            byte[] result = new byte[0];
            for(int i = 0; i < nodeIds.length; ++i){
            	
            	byte[] temp = concat(longToBytes(nodeIds[i]), generateKey(nodeIds[i], aacsKey));
            	result = concat(result, temp );
               
            }//end for - i
            byte[] pass = KeyTree.createAESKeyMaterial(passwd); 
            Key sec = new SecretKeySpec(pass, "AES");
			
			Cipher AesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            AesCipher.init(Cipher.ENCRYPT_MODE, sec);
            byte[] byteCipherText = AesCipher.doFinal(result);

            
            Mac mac = Mac.getInstance("HmacSHA1");
			SecretKeySpec secret = new SecretKeySpec(passwd.getBytes(), mac.getAlgorithm());
			mac.init(secret);
			byte[] auth = mac.doFinal(byteCipherText);

			fout.write(byteCipherText);
			fout.write(auth);
			
			fout.flush();
            fout.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }//end writeKeys()
    
    // Parse the command line and write the keys.
    // Usage: PlayerKeys <aacs pwd> <player id> <player keyfile password>
    public static void main(String[] args){
        try{
            if(args.length != 3){
                System.out.println("Usage: PlayerKeys <AACSPwd> <PlayerId> <KeyfilePwd>");
                
                return;
            }
            
            String aacsPasswd = args[0];
            long playerId = Integer.parseInt(args[1]);
            String keyfilePasswd = args[2];
            
            
            PlayerKeys playerKeys = new PlayerKeys();
            
            playerKeys.writeKeys(playerId, aacsPasswd, keyfilePasswd);
        }catch(Exception e){
            e.printStackTrace();
        }
    }//end main()
}//end class
