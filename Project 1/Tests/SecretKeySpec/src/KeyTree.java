/*
 * INFO0045: Assignment 1
 *
 * Provides an interface to the binary tree structure which is used to select
 * keys to provide to the DVD players and for encrypting files.
 *
 * There are 2^32 players, and each player has an associated player id in the range
 * [0, 2^32-1] that is represented as a java 64-bit long type.
 *
 * The key tree is a binary tree of height 33, where each leaf is associated with a
 * single player.  Each node in the tree is represented by a unique integer (again
 * as a long).  Note that each leaf has 2 associated IDs: the player ID of the player
 * and the Node ID associated with the node in the tree.
 *
 * There are two key methods in this class:
 * long[] getPathNodes(long PlayerID);
 * long[] getCoverSet(long exlcudedPlayers);
 * both take Player IDs as input and output Node IDs.
 */

import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class KeyTree {
    
    private final static int TREE_DEPTH = 33;
    
    // Creates a new KeyTree object w/ fixed tree depth 33
    public KeyTree(){
        depth = TREE_DEPTH;
        maxLeafId = pow2(depth-1)-1;
        minLeafNodeId = maxLeafId+1;
        maxLeafNodeId = minLeafNodeId + maxLeafId;
    }//end constructor
    
    // Returns an array of Node IDs associated with the tree nodes
    // along the path from the root to the leaf associated with
    // the given player ID (in that order)
    public long[] getPathNodes(long playerId){
        long[] nodes = new long[depth];
        
        Iterator iter = getLeaf(playerId);
        
        for(int i = depth-1; i >=0; --i){
            nodes[i] = iter.getNodeId();
            if(i > 0)
                iter.toParent();
        }//end for - i
        
        return nodes;
    }//end getPahtNodes
    
    // Returns an array of Node IDs that are a covering set for
    // all players EXCEPT the ones passed in the array excludedPlayers.
    // Specifically, no player identified in excludedPlayers will
    // be a child of any node in the returned array, and every
    // player not in excludedPlayers is a child of exactly one
    // node in the returned array.
    public long[] getCoverSet(long[] excludedPlayers){
        Arrays.sort(excludedPlayers);
        int numExcl = excludedPlayers.length;
        
        if(numExcl == 0)
            return new long[] {ROOT_ID};
        
        List<Long> coverSet = new ArrayList<Long>();
        
        long min ;
        long max = -2;
        
        for(int i = 0; i < numExcl; ++i){
            min = max+2;
            max = excludedPlayers[i] - 1;
            coverSet.addAll(getCoverSet(min, max));
        }//end for - i
        
        if(excludedPlayers[numExcl-1] < maxLeafId)
            coverSet.addAll(getCoverSet(excludedPlayers[numExcl-1]+1,
                                         maxLeafId));
        
        long[] csArr = new long[coverSet.size()];
        
        for(int i = 0; i < csArr.length; ++i)
            csArr[i] = coverSet.get(i);
        
        Arrays.sort(csArr);
        
        return csArr;
    }//end getCoverSet()
    
    //Takes a password and returns a byte array that can be used
    // to build an AES Key, e.g. using SecretKeySpec
    public static byte[] createAESKeyMaterial(String password)
    throws NoSuchAlgorithmException{
        if ((password == null) || (password.equals("")))
            throw new IllegalArgumentException("You must provide a password in order to generate an AES Key!");
        
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] output = md.digest();
        
        return output;
    }//end createAESKeyMaterial()
    
    private long maxLeafId;
    private long minLeafNodeId;
    private long maxLeafNodeId;
    private int depth ;
    
    private final static long ROOT_ID = 1;
    
    private Iterator getRoot(){
        return new Iterator(ROOT_ID);
    }//end getRoot()
    
    private Iterator getLeaf(long leafId){
        return new Iterator( getLeafNodeId(leafId));
    }//end getLeaf()
    
    // Translates "player ids" (0-2^n-1) to the associated
    // node id for that leaf in the tree
    private long getLeafNodeId(long leafId){
        return leafId + minLeafNodeId;
    }//end getLeafNodeID()
    
    
    // computes the covering set for the players with IDs
    // between minLeafId and maxLeafId, inclusive
    private List<Long> getCoverSet(long cminLeafId, long cmaxLeafId){
        List<Long> coverSet = new ArrayList<Long>();
        
        if( cmaxLeafId < cminLeafId)
            return coverSet;
        
        Iterator min = getLeaf(cminLeafId);
        Iterator max = getLeaf(cmaxLeafId);
        
        Iterator U1 = min.clone();
        computeCoverBound(min, max, U1);
        Iterator newMin = insertUCoverNodes(U1, max, coverSet);
        
        if(newMin.getNodeId() < max.getNodeId()){
            Iterator V1 = max.clone();
            computeCoverBound(newMin, max, V1);
            insertVCoverNodes(V1, newMin, coverSet);
        }
        
        return coverSet;
    }//end getCoverSet()
    
    private void computeCoverBound(Iterator min, Iterator max, Iterator node){
        Iterator nextNode = node.clone();
        
        nextNode.toParent();
        
        while(nextNode.getRightLeafNodeId() <= max.getNodeId() &&
              nextNode.getLeftLeafNodeId() >= min.getNodeId()){
            node.toParent();
            nextNode.toParent();
        }//end while
    }//end computeCoverBound()
    
    private Iterator insertUCoverNodes(Iterator U1, Iterator max, List<Long> coverSet ){
        Iterator Ui = U1.clone();
        Iterator nextUi = Ui.clone();
        
        while(true){
            coverSet.add(Ui.getNodeId());
            
            if(nextUi.isRoot())
                break;
            
            if(nextUi.isRightChild())
                nextUi.toParent();
            
            if(!nextUi.hasRightSibling())
                break;
            
            nextUi.toRightSibling();
            
            if(nextUi.getRightLeafNodeId() > max.getNodeId())
                break;
            
            if(Ui.isRightChild())
                Ui.toParent();
            
            Ui.toRightSibling();
        }//end while
        
        return new Iterator(Ui.getRightLeafNodeId()+1);
    }//end insertUCoverNodes()
    
    private void insertVCoverNodes(Iterator V1, Iterator min, List<Long> coverSet){
        Iterator Vi = V1.clone();
        Iterator nextVi = Vi.clone();
        
        while(true){
            coverSet.add(Vi.getNodeId());
            
            if(nextVi.isRoot())
                break;
            
            if(nextVi.isLeftChild())
                nextVi.toParent();
            
            if(!nextVi.hasLeftSibling())
                break;
            
            nextVi.toLeftSibling();
            
            if(nextVi.getLeftLeafNodeId() < min.getNodeId())
                break;
            
            if(Vi.isLeftChild())
                Vi.toParent();
            
            Vi.toLeftSibling();
        }//end while
    }//end insertVCoverNodes()
    
    // The nested class Iterator is used for traversing the implicit tree
    // structure of the KeyTree
    class Iterator{
        
        private long nodeId;
        
        public Iterator(long nodeId){
            this.nodeId = nodeId;
            assert isValid();
        }//end constructor
        
        public Iterator clone(){
            return new Iterator(nodeId);
        }//end clone()
        
        public final long getNodeId(){
            return nodeId;
        }//end getNodeId()
        
        public final void toLeftChild(){
            assert !isLeaf();
            nodeId= 2*nodeId;
        }//end toLeftChild()
        
        public final void toRightChild(){
            assert !isLeaf();
            nodeId = 2*nodeId + 1;
        }//end toRightChild()
        
        public final void toParent(){
            assert !isRoot();
            nodeId = nodeId / 2;
        }//end toParent()
        
        public final void toLeftSibling(){
            assert hasLeftSibling();
            nodeId--;
        }//end toLeftSibling()
        
        public final void toRightSibling(){
            assert hasRightSibling();
            nodeId++;
        }//end toRightSibling()
        
        public final boolean isRoot(){
            return (nodeId == ROOT_ID);
        }//end isRoot()
        
        public final boolean isLeaf(){
            return nodeId >= minLeafNodeId;
        }//end isLeaf()
        
        public final boolean hasLeftSibling(){
            return !isPowerOfTwo(nodeId);
        }//end hasLeftSibling()
        
        public final boolean hasRightSibling(){
            return !isPowerOfTwo(nodeId+1);
        }//end hasRightSibling()
        
        public final boolean isRightChild(){
            return !isRoot() && (nodeId % 2 == 1);
        }//end isRightChild()
        
        public final boolean isLeftChild(){
            return !isRoot() && (nodeId % 2 == 0);
        }//end isLeftChild()
        
        public final long getLeftLeafNodeId(){
            int nodeDepth = log2(nodeId) + 1;
            int leafDeltaDepth = depth - nodeDepth;
            
            return pow2(leafDeltaDepth) * nodeId; 
        }//end getLeftLeafNodeId()
        
        public final long getRightLeafNodeId(){
            int nodeDepth = log2(nodeId) + 1;
            int leafDeltaDepth = depth - nodeDepth;
            
            long fact = pow2(leafDeltaDepth);
            
            return fact * nodeId + fact - 1; 
        }//end getRightLeafNodeId()
        
        public final boolean isValid(){
            // allows one invalid case to simplify some code
            return nodeId > 0 && nodeId <= maxLeafNodeId+1;
        }//end isValid()
        
        public final boolean isParentOf(long nodeId){
            if(isRoot())
                return true;
            
            Iterator iter = new Iterator(nodeId);
            
            while(iter.getNodeId() > getNodeId()){
                if(iter.equals(this))
                    return true;
                
                iter.toParent();
            }//end while
            
            return false;
        }//end isParentOf()
        
        @Override
        public boolean equals(Object obj){
            if(obj instanceof Iterator)
                return ((Iterator)obj).nodeId == nodeId;
            else
                return false;
        }//end equals()
    }//end inner class
    
    
    // Some functions for dealing powers of 2 in the 
    // binary tree. Not meant to be fast, just short and to the point.
    private static final boolean isPowerOfTwo(long num){
        return (num != 0) &&  ( (num-1)&num ) == 0;
    }//end isPowerOfTwo()
    
    private static final int log2(long num){
        assert num > 0;
        
        int r = 0;
        while((num >>= 1) != 0)
            ++r;
        
        return r;
    }//end log2()
    
    private static final long pow2(int pow){
        long val = 1;
        val <<= pow;
        
        return val;
    }//end pow2()
}//end class
