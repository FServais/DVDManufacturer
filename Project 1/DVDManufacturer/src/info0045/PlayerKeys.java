/*
 * INFO0045: Assignment 1
 *
 * Given a player ID, generates a set of keys for that player and write it
 * to a file
 */

package info0045;

import java.io.*;

public class PlayerKeys{
    
    // Should write the encrypted keyfile to the filename specified
    // by DVDPlayer.getKeyFilename(playerId). Now it only writes
    // the node Ids in plaintext to the file. You need to generate
    // the keys associated with the node IDs and store them in the file
    // encrypted.
    public void writeKeys(long playerId, String passwd){
        KeyTree keyTree = new KeyTree();
        
        // get the associated nodes
        long[] nodeIds = keyTree.getPathNodes(playerId);
        
        try{
            String keyFilename = DVDPlayer.getKeyFilename(playerId);
            BufferedWriter fout = new BufferedWriter(new FileWriter(keyFilename));
            
            for(int i = 0; i < nodeIds.length; ++i){
                fout.write(Long.toString(nodeIds[i]));
                fout.newLine();
            }//end for - i
            
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
            
            playerKeys.writeKeys(playerId, keyfilePasswd);
        }catch(Exception e){
            e.printStackTrace();
        }
    }//end main()
}//end class
