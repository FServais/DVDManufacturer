import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xml.internal.security.utils.Base64;


public class Main {

	public static void main(String[] args) {
		try {
			String content = "azertyuiop";
			
			Mac mac = Mac.getInstance("HmacSHA512");
			SecretKeySpec secret = new SecretKeySpec("password".getBytes(), mac.getAlgorithm());
			mac.init(secret);
			
			byte[] digest = mac.doFinal(content.getBytes());
			System.out.println("Hash : " + Base64.encode(digest));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
