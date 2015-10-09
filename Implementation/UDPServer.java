/* 
 * UDPServer.java 
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

/**
 * UDPServer  class
 *
 */

public class UDPServer {
	DatagramSocket serverSocket;
	DatagramPacket receivePacket;
	DatagramPacket sendPacket;
	final int DEFAULT_DNS_SERVER_PORT = 53;
	final int BUFFER_SIZE = 512;
	byte dnsBuffer[];
	int port;
	
	
	/**
	 * UDPServer  Constructor
	 * Creates socket on the port requested.
	 * 
	 * @param port
	 *
	 */
	public UDPServer(int port) {
		this.port = port;
		createSocket(port);
		dnsBuffer = new byte[BUFFER_SIZE];
	}
	
	/**
	 * UDPServer  Constructor
	 * Creates socket on the default port.
	 *
	 */
	
	public UDPServer() {
		port = DEFAULT_DNS_SERVER_PORT;
		createSocket(DEFAULT_DNS_SERVER_PORT);
		dnsBuffer = new byte[BUFFER_SIZE];
	}
	
	public DatagramSocket createSocket(int port) {
		try {
			serverSocket = new DatagramSocket(port);
			
		} catch (SocketException e) {
			e.printStackTrace();
		}
		return serverSocket;	
	}
	
	/**
	 * Receive buffer method.
	 *
	 */
	
	public byte[] receive() throws IOException {
		receivePacket = new DatagramPacket(dnsBuffer, dnsBuffer.length);
		serverSocket.receive(receivePacket);
		return dnsBuffer;
	}
	
	/**
	 * Send buffer method.
	 *
	 */
	
	public boolean send(InetAddress IP, int p, byte buf[], int size) throws IOException {
		sendPacket = new DatagramPacket(buf, size, IP, p);
		serverSocket.send(sendPacket);
		return true;
	}
	
}
