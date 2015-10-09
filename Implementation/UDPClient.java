/* 
 * UDPClient.java 
 * 
 * Version: 
 *     $Id$ 1.1
 *     
 * @author	Pranav Sai Kethe
 * @author	Sandeep Kumar Ragila
 * 
 */

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

/* 
 * UDPClient Class 
 * 
 */

public class UDPClient {
	byte buffer[];
	InetAddress inetAddress;
	final int BUFFER_SIZE = 512;
	DatagramSocket clientSocket;
	DatagramPacket sendPacket, receivePacket;
	

	UDPClient(String IP) throws UnknownHostException, SocketException {
		inetAddress = InetAddress.getByName(IP);
		clientSocket = new DatagramSocket();
	}
	UDPClient() throws SocketException {
		clientSocket = new DatagramSocket();
	}
	
	public byte[] receive() throws IOException {
		buffer = new byte[BUFFER_SIZE];
		receivePacket = new DatagramPacket(buffer, buffer.length);
		clientSocket.receive(receivePacket);
		return buffer;
	}
	
	public boolean send(byte buffer[], int size) throws IOException {
		sendPacket = new DatagramPacket(buffer, size, inetAddress, 53);
		clientSocket.send(sendPacket);
		return true;
	}	
	
	public boolean sendP(byte buffer[], InetAddress IP, int p) throws IOException {
		sendPacket = new DatagramPacket(buffer, buffer.length, IP, p);
		clientSocket.send(sendPacket);
		return true;
	}
	
	public void close () {
		clientSocket.close();
	}
}
