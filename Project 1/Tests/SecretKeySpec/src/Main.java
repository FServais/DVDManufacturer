import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

import java.util.*;


public class Main {

	public static void main(String[] args) {
		/* 
         * ==========================================
         *			 Generation of K_enc
         * ==========================================
         */
		
		KeyGenerator kg = null;
		try {
			kg = KeyGenerator.getInstance("HmacSHA512");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        kg.init(256);

        SecretKey kt = kg.generateKey();
        System.out.println("Length of Kt = " + kt.getEncoded().length);
	        
        Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA512");
	        mac.init(kt);
	
	        byte[] kEnc = mac.doFinal("CONTENT".getBytes()); // K_enc = HMAC(K_t, "enc")
	        System.out.println("Length of kEnc = " + kEnc.length);
	        SecretKeySpec kEncSpec = new SecretKeySpec(kEnc, "AES");
	        
	        
	        /* 
	         * ==========================================
	         *			 Encryption of the content
	         * ==========================================
	         */
	        
	        Cipher cipher = null;
	    	cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, kEncSpec);
			
			byte[] IV = cipher.getIV();
			System.out.println("IV : " + Base64.getEncoder().encodeToString(IV));
			
			byte[] encryptedBytes = cipher.doFinal("CONTENT".getBytes());
			
			System.out.println("Encrypted : " + Base64.getEncoder().encodeToString(encryptedBytes));
			
			cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, kEncSpec, new IvParameterSpec(IV));
			
			System.out.println("Decrypted : " + Base64.getEncoder().encodeToString(cipher.doFinal(encryptedBytes)));
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
