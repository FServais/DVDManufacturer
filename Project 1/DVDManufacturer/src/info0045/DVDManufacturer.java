/*
 * INFO0045: Assignment 1
 *
 * Encrypts a given content file with a set of guaranteed not to include any
 * player's keys in the revocation list, but which will allow any other player to
 * properly decrypt the content.
 */

package info0045;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.lang.StringBuilder;

public class DVDManufacturer{
    
    private final static String revocationFilename = "revoke.lst";
    
    public DVDManufacturer(){
        
    }
    
    // Encrypts the content. You need to implement this function:
    // right now it just copies the input content file to an output
    // file and deletes the original content file. Your output file
    // should be named by a call to getOutputFilename.
    public void encryptContent( String title, String contentFilename,
                               long [] revocationList, String aacsPasswd){
        
        String encFilename = getOutputFilename(contentFilename);
        
        try{
            FileInputStream fin = new FileInputStream(contentFilename);
            FileOutputStream fout = new FileOutputStream(encFilename);
            
            StringBuilder sb = new StringBuilder();
            int inchar;
            while((inchar = fin.read()) != -1){
                sb.append((char)inchar);
                fout.write(inchar);
            }

            String content = sb.toString();

            long[] idsCover = new KeyTree().getCoverSet(revocationList);
            
            String encryptedContent = encrypt(title, content, idsCover, aacsPasswd);            
            
            fin.close();
            fout.close();
            
            //new File(contentFilename).delete();
            
        }catch( Exception e ){
            e.printStackTrace();
        }
    }//end encryptContent()
    
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
    
    // Parses the revocation file, assumed to be at revoke.lst
    // The format is just text integer player ids separated by newlines
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


    /**
     * Function that encrypt a content using a set of keys. One of the keys is need to decrypt this content.
     * @param  content   Content to encrypt.
     * @param  coverKeys Set of keys that will encrypt the content.
     * @return           Encrypted content, in the form header||encrypted content.
     */
    private String encrypt(String content_title, String content, long[] coverIds, String aacsPasswd){
    	StringBuilder header = new StringBuilder();
    	
        /* 
         * ==========================================
         *			 Generation of K_t
         * ==========================================
         */
        KeyGenerator kg = null;
		try {
			kg = KeyGenerator.getInstance("HmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
        //kg.init(256);

        SecretKey kt = kg.generateKey();
        if(kt != null)
        	System.out.println("Key : " + Base64.getEncoder().encodeToString(kt.getEncoded()) + " : (" + kt.getEncoded().length + " Bytes)");
        
        byte[] ktBytes = kt.getEncoded(); 
        SecretKeySpec ktSpec = new SecretKeySpec(ktBytes, "HmacSHA1");
        
        try {
        	/* 
             * ==========================================
             *			 Generation of K_enc
             * ==========================================
             */
	        byte[] kEnc = deriveKeyEnc(ktBytes);
	        SecretKey kEncSpec = new SecretKeySpec(kEnc, "AES");
	        
	        
	        /* 
             * ==========================================
             *			 Generation of K_mac
             * ==========================================
             */
            
	        byte[] kMac = deriveKeyMac(ktBytes);
	        System.out.println("Length of K_mac = " + kMac.length);
	        
	        
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
			
			byte[] encryptedBytes = cipher.doFinal(content.getBytes());
			
			System.out.println("Encrypted content : " + Base64.getEncoder().encodeToString(encryptedBytes));
			
			
			/* 
             * ==========================================
             *			Translate nodes to keys
             * ==========================================
             */
			
			PlayerKeys pk = new PlayerKeys();
			HashMap<Long, byte[]> setKeys = new HashMap<Long, byte[]>();
			
			for(long id : coverIds)
				setKeys.put(id, pk.generateKey(id, aacsPasswd));
			
			
			/* 
             * ==========================================
             *		Encrypt K_enc with set of keys
             * ==========================================
             */
			HashMap<Long, byte[]> encryptionsKt = new HashMap<Long, byte[]>();
			Iterator it = setKeys.entrySet().iterator();
			
			Cipher keyCipher = Cipher.getInstance("AES");
			while(it.hasNext()){
				Map.Entry<Long, byte[]> pair = (Map.Entry<Long, byte[]>)it.next();
				keyCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(pair.getValue(), "AES"));
				
				encryptionsKt.put(pair.getKey(), cipher.doFinal());
			}
			
			
			
			
			/* ================ DEBUG =============== */
			/*
			 try{
		            FileOutputStream fout = new FileOutputStream("encoded.enc");
		            fout.write(encryptedBytes);
		            fout.close();
		          
		     }catch( Exception e ){
		    	 e.printStackTrace();
		     }
			 
			 byte[] filecontent = null;
			 try{
				 	File file = new File("encoded.enc");
		            FileInputStream fin = new FileInputStream(file);
		            
		            filecontent = new byte[(int)file.length()];
		            
		            fin.read(filecontent);
		            
		            fin.close();
		          
		     }catch( Exception e ){
		    	 e.printStackTrace();
		     }
			
			 encryptedBytes = filecontent;
			 
			
			*/
			/* ================ END DEBUG =============== */
			// DECRYPT
			cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			try {
				cipher.init(Cipher.DECRYPT_MODE, kEncSpec, new IvParameterSpec(IV));
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			try {
				System.out.println("Plain text : " + new String(cipher.doFinal(encryptedBytes), "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
        
        
        
        
		return content;
    }
    
    
    private byte[] deriveKeyEnc(byte[] kt){
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
    

}//end class
