import java.nio.ByteBuffer;
import java.util.ArrayList;


public class MainBytes {

	public static void main(String[] args) {
		ArrayList<Byte> encryption = new ArrayList<Byte>();
		String content_title = "azerty";
		
		int titleSize = content_title.getBytes().length;
        byte nodeSize = 8; // Node in a long -> 8 bytes
        byte keySize = 16; // Key on 16 bytes
        
        addArrayToListByte(encryption, intToBytes(titleSize));
        
        System.out.println("List : " + encryption.toString());
        
        encryption.add(nodeSize);
        
        System.out.println("List : " + encryption.toString());
	}
	
	private static void addArrayToListByte(ArrayList<Byte> list, byte[] array){
    	for(byte item : array)
    		list.add(item);
    }
    
    private static byte[] longToBytes(long x){
    	return ByteBuffer.allocate(8).putLong(x).array();
    }
    
    private static long bytesToLong(byte[] x){
		long result = 0;
		for (byte value : x){
		    result <<= 8;
		    result += value;
		}
		
		return result;
	}
    
    private static byte[] intToBytes(int x){
    	return ByteBuffer.allocate(4).putInt(x).array();
    }
    
    private static int bytesToInt(byte[] x){
		int result = 0;
		for (byte value : x){
		    result <<= 4;
		    result += value;
		}
		
		return result;
	}
}
