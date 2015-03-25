import java.io.ByteArrayOutputStream;
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
		
		try {
			String content = "aaaaaasfdg";
			Cipher cipher = Cipher.getInstance("AES");
			
			KeyGenerator kg = null;
			try {
				kg = KeyGenerator.getInstance("AES");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
	        kg.init(128);

	        SecretKey kt = kg.generateKey();
			
	        cipher.init(Cipher.ENCRYPT_MODE, kt);
	        
	        System.out.println("Content to encrypt : " + Base64.getEncoder().encodeToString(content.getBytes()));
	        byte[] enc = cipher.doFinal(content.getBytes());
	        
	        cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.DECRYPT_MODE, kt);
	        
	        byte[] plain = cipher.doFinal(enc);
	        System.out.println("Plain text : " + Base64.getEncoder().encodeToString(plain));
	        
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        
	        
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}

}
