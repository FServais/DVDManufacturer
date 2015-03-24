/*
 * INFO0045: Assignment 1
 *
 * Should decrypt the encrytped file given or indicate one of two posible failures:
 * 1) player revocation
 * 2) content file MAC failure
 */

package info0045;

import javax.crypto.*;
import java.io.*;

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
