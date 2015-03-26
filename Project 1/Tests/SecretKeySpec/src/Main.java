
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.util.*;
import java.util.Map.Entry;


public class Main {
	
	public static void main(String[] args) {
		
		BufferedReader br = null;
		
		try {
			br = new BufferedReader(new FileReader("content.txt.enc"));
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
			Iterator<Entry<Long, String>> it = nodesKeys.entrySet().iterator();
			while(it.hasNext()){
				Map.Entry<Long, String> pair = (Entry<Long, String>) it.next();
				System.out.println("<Key, Value> = <" + pair.getKey() + ", " + pair.getValue() + ">");
			}
			
			long nodeID = 8044;
			String aacsPasswd = "aacspass";
			KeyTree keyTree = new KeyTree();
			
			byte[] key = generateKey(nodeID, aacsPasswd);
			
			
			if(!nodesKeys.containsKey(nodeID)){
				System.out.println("Key not contained");
				return;
			}
			
			byte[] keyFile = DatatypeConverter.parseHexBinary(nodesKeys.get(nodeID));
			
			Cipher keyCipher = Cipher.getInstance("AES");
			keyCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(new PlayerKeys().generateKey(nodeID, aacsPasswd), "AES"));
			byte[] plain_kt = keyCipher.doFinal(keyFile);
			System.out.println("Plain text K_t : " + DatatypeConverter.printHexBinary(plain_kt));
			
			
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
			
			
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	protected static byte[] generateKey(long nodeId, byte[] aacsKey){
		
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
		
		return md.digest(toReturn);
		
	}
    
	
	public static byte[] longToBytes(long x) {
		
	    ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE);
	    buffer.putLong(x);
	    return buffer.array();
	}
	
	
	protected static byte[] generateKey(long nodeId, String aacsPasswd){
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
}
