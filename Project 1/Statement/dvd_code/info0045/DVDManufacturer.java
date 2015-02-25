/*
 * INFO0045: Assignment 1
 *
 * Encrypts a given content file with a set of guaranteed not to include any
 * player's keys in the revocation list, but which will allow any other player to
 * properly decrypt the content.
 */

package info0045;

import java.io.*;
import java.util.*;

public class DVDManufacturer{
    
    private final static String revocationFilename = "revoke.lst";
    
    public DVDManufacturer(){
        
    }
    
    // Encrypts the content. You need to implement this function:
    // right now it just copies the input content file to an output
    // file and deletes the original content file. Your output file
    // should be named by a call to getOutputFilename.
    public void encryptContent( String title, String contentFilename,
                               long [] revocationList ){
        
        String encFilename = getOutputFilename(contentFilename);
        
        try{
            FileInputStream fin = new FileInputStream(contentFilename);
            FileOutputStream fout = new FileOutputStream(encFilename);
            
            int inchar;
            while((inchar = fin.read()) != -1)
                fout.write(inchar);
            
            fin.close();
            fout.close();
            
            new File(contentFilename).delete();
            
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
            
            manu.encryptContent(title, contentFile, revList);
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
}//end class
