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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.lang.StringBuilder;
import java.nio.ByteBuffer;

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
            }

            String content = sb.toString();
            
            // Cover set
            long[] idsCover = new KeyTree().getCoverSet(revocationList);
            
            byte[] encryptedContent = encrypt(title, content, idsCover, aacsPasswd);            
            
            fout.write(encryptedContent);
            
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
            //kg.init(256);
    
            SecretKey kt = kg.generateKey();
            byte[] ktBytes = kt.getEncoded(); 

            
            /* 
             * ==========================================
             *           Generation of K_enc
             * ==========================================
             */
            byte[] kEnc = deriveKeyEnc(ktBytes);
            SecretKey kEncSpec = new SecretKeySpec(kEnc, "AES");
            
            
            /* 
             * ==========================================
             *           Generation of K_mac
             * ==========================================
             */
            byte[] kMac = deriveKeyMac(ktBytes);
            
            
            /* 
             * ==========================================
             *           Encryption of the content
             * ==========================================
             */
            
            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, kEncSpec);
            
            byte[] IV = cipher.getIV();
            
            byte[] encryptedBytes = cipher.doFinal(content.getBytes());
            String encryptedContentString = DatatypeConverter.printHexBinary(encryptedBytes);

            
            /* 
             * ==========================================
             *          Translate nodes to keys
             * ==========================================
             */
            
            PlayerKeys pk = new PlayerKeys();
            HashMap<Long, byte[]> setKeys = new HashMap<Long, byte[]>();
            
            for(long id : coverIds)
                setKeys.put(id, pk.generateKey(id, aacsPasswd));
            
            
            /* 
             * ==========================================
             *      Encrypt K_t with set of keys
             * ==========================================
             */
            HashMap<Long, byte[]> encryptionsKt = new HashMap<Long, byte[]>();
            HashMap<Long, String> encryptionsKt_hex = new HashMap<Long, String>();
            
            
            Iterator<Map.Entry<Long, byte[]>> it = setKeys.entrySet().iterator();
            
            Cipher keyCipher = Cipher.getInstance("AES");
            while(it.hasNext()){
                Map.Entry<Long, byte[]> pair = it.next();
                keyCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(pair.getValue(), "AES"));
                
                encryptionsKt.put(pair.getKey(), keyCipher.doFinal(kEnc));
                //encryptionsKt_hex.put(pair.getKey(), bytesToHex(keyCipher.doFinal(kEnc)));
                encryptionsKt_hex.put(pair.getKey(), DatatypeConverter.printHexBinary(keyCipher.doFinal(ktBytes)));
            }
            
            
            /* 
             * ==========================================
             *             Generate the file 
             * ==========================================
             */
            
            int titleSize = content_title.length();
            int numOfKeys = setKeys.size();
            byte nodeSize = 8; // Node in a long -> 8 bytes
            byte keySize = 16; // Key on 16 bytes
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
                addArrayToListByte(encryption, concatenateBytes(longToBytes(pair.getKey()), pair.getValue())); // node||key
            }
            
            encryption.add(ivSize);
            addArrayToListByte(encryption, IV); // Initialization vector
            
            addArrayToListByte(encryption, intToBytes(contentSize));
            addArrayToListByte(encryption, encryptedBytes); //Content
            
            /*
            StringBuilder header = new StringBuilder();
            header.append(content_title + "\n");

            Iterator<Map.Entry<Long, String>> it_hex = encryptionsKt_hex.entrySet().iterator();
            while(it_hex.hasNext()){
                Map.Entry<Long, String> pair = it_hex.next();
                header.append(pair.getKey() + " " + pair.getValue() + "\n");
            }
            
            StringBuilder fileString = new StringBuilder();
            fileString.append(header);
            fileString.append(DatatypeConverter.printHexBinary(IV) + "\n");
            fileString.append(encryptedContentString + "\n");
            */
            
            /* 
             * ==========================================
             *                Generate MAC
             * ==========================================
             */
            /*
            String MAC = DatatypeConverter.printHexBinary(generateMAC(fileString.toString(), kMac));
            fileString.append(MAC);
            
            return fileString.toString();
            */
            
            byte[] macFile = generateMAC(listToArrayBytes(encryption), kMac);
            addArrayToListByte(encryption, macFile);
            
            return listToArrayBytes(encryption);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
      
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
    
    
    private byte[] generateMAC(String content, byte[] kMac){
        return generateMAC(content.getBytes(), kMac);
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
    
    
    private void addArrayToListByte(ArrayList<Byte> list, byte[] array){
    	for(byte item : array)
    		list.add(item);
    }
    
    private byte[] longToBytes(long x){
    	return ByteBuffer.allocate(8).putLong(x).array();
    }
    
    private long bytesToLong(byte[] x){
		long result = 0;
		for (byte value : x){
		    result <<= 8;
		    result += value;
		}
		
		return result;
	}
    
    private byte[] intToBytes(int x){
    	return ByteBuffer.allocate(4).putInt(x).array();
    }
    
    private int bytesToInt(byte[] x){
		int result = 0;
		for (byte value : x){
		    result <<= 4;
		    result += value;
		}
		
		return result;
	}
    
    /**
     * 
     * Source: http://stackoverflow.com/a/5513188
     * @param a
     * @param b
     * @return
     */
    private byte[] concatenateBytes(byte[] a, byte[] b){
    	byte[] c = new byte[a.length + b.length];
    	System.arraycopy(a, 0, c, 0, a.length);
    	System.arraycopy(b, 0, c, a.length, b.length);
    	
    	return c;
    }
    
    
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
