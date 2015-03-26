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
        
        byte[] test = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xD4};
        System.out.println("Hex to int : " + bytesToInt(test));
        
        long i = 505;
        byte[] i_bytes = longToBytes(i);
        System.out.println(String.format("0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X", i_bytes[0], i_bytes[1], i_bytes[2], i_bytes[3], i_bytes[4], i_bytes[5], i_bytes[6], i_bytes[7]));
	}
	
	private static void addArrayToListByte(ArrayList<Byte> list, byte[] array){
    	for(byte item : array)
    		list.add(item);
    }
    
    private static byte[] longToBytes(long x){
    	return ByteBuffer.allocate(8).putLong(x).array();
    }
    
    private static long bytesToLong(byte[] x){
    	ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(x);
        buffer.flip();//need flip 
        return buffer.getLong();
	}
    
    private static byte[] intToBytes(int x){
    	return ByteBuffer.allocate(4).putInt(x).array();
    }
    
    private static int bytesToInt(byte[] b){
    	/*
		int result = 0;
		for (byte value : x){
		    result <<= 4;
		    result += value;
		}
		
		return result;
		*/
    	return   b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
	}
}
