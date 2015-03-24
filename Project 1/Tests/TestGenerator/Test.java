import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.*;

import java.lang.StringBuilder;

public class Test{
    

    public static void main( String[] args ){
        // Generation of K_t
        KeyGenerator kg = null;
        try {
            kg = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kg.init(256);

        SecretKey key = kg.generateKey();
        if(key != null)
            System.out.println(Base64.encodeBase64String(key.getEncoded()));
        
    }//end main()
 
}//end class
