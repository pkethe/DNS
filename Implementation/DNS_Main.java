/* 
 * DNSMain.java 
 * 
 * Version: 
 *     $Id$ 1.1
 *     
 * @author	Pranav Sai Kethe
 * @author	Sandeep Kumar Ragila
 * 
 */
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * The program DNS_Main behaves as Local Name server.
 *
 */

public class DNS_Main implements Runnable {

	short ID;
	int port;
	InetAddress IP;
	byte tDnsBuffer[];
	static UDPServer localNameServer;
	static List<Integer> queryRequests = Collections.synchronizedList(new ArrayList<Integer>());
	static Map<String, RR> cache = Collections.synchronizedMap(new HashMap<String, RR>());
	String rootServers[] = { "192.228.79.201", "198.41.0.4","192.33.4.12", "199.7.91.13", "192.203.230.10",
			"192.5.5.241", "192.112.36.4", "128.63.2.53", "192.36.148.17", "192.58.128.30",
			"193.0.14.129", "199.7.83.42", "202.12.27.33"};


	public DNS_Main(short ID, int port, InetAddress IP, byte b[]) {	
		this.ID = ID;
		this.port = port;
		this.IP = IP;
		this.tDnsBuffer = b;
	}

	public static void main(String[] args) {
		localNameServer = new UDPServer();
		System.out.println("LNS: Started, port" + localNameServer.port);
		byte mBuffer[] = null;

		while (true) {
			try {
				mBuffer = localNameServer.receive();
			} catch (Exception e) {
				System.err.println("LNS: Error while receiving");
			}

			// ID
			short ID = (short)((mBuffer[0]&0xff) << 8|(mBuffer[1]&0xff));

			new Thread(new DNS_Main(ID, localNameServer.receivePacket.getPort(), localNameServer.receivePacket.getAddress(), mBuffer)).start();
		}
	}

	public void run() {
		// Extract query
		DNS d1 = new DNS();
		d1.extractQuery(tDnsBuffer);

		if (d1.getQNAME().equals("local") || d1.getQNAME().length() < 1) {
			// exit thread.
		} else {
			// Check in cache,
			boolean inCache = false;
			synchronized(cache) {
				inCache = cache.containsKey(d1.getQNAME());
			}
			// if exists return response;
			if (inCache) {
				
				synchronized(cache) {
					RR record;
					record = cache.get(d1.getQNAME());
					try {
						
						record.Record[1] = (byte)(ID & 0xff);
						record.Record[0] = (byte)((ID >> 8) & 0xff);
						localNameServer.send(IP, port, record.Record, record.position);
						
					//	System.out.println("In cache... sent response");
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} else {  // else do query with root servers
				// try with different root servers till we get valid response
				String QNAME_HOLDER = d1.getQNAME();
				for (int i = 0; i < rootServers.length; i++) {
					// Build Query
					int position = 0;
					position = d1.buildQuery(tDnsBuffer);

					try {

						UDPClient uc = new UDPClient(rootServers[i]);
						uc.send(tDnsBuffer, position);
						byte buf[];
						buf = uc.receive();	
						d1.clearAdditional();
						d1.clearAuthoritative();
						d1.extractResponse(buf);

						byte buf2[] = null;
						int y = 0;
						
						while(true) {
							// check if answer is available
							if ((d1.R_ANCOUNT > 0) && buf2 !=null) {
								// check if the response has Canonical name
								if (d1.isCNAME) {
									d1.QNAME = d1.IP_list.get(0);
									d1.buildQuery(tDnsBuffer);
									d1.R_ANCOUNT = 0;
								} else {
									// cache and send back response
									// build response according to the QNAME received.
									if (d1.cr.size() > 0) {
										buf2 = d1.buildResponse(buf2, QNAME_HOLDER);
										position = d1.endPointer;
									} else {
										synchronized(cache) {
											cache.put(QNAME_HOLDER, new RR(QNAME_HOLDER, buf2, 1000, position));
										}
									}			
									localNameServer.send(IP, port, buf2, position);
									break;
								}

							// if additional info present
							} else if (d1.AA_list.size() > 0) {	
								if (d1.isCNAME) {
									d1.isCNAME = false;
								}
								UDPClient uca = new UDPClient(d1.AA_list.get(0));
								uca.send(tDnsBuffer, position);

								buf2 = uca.receive();
								d1.clearAdditional();
								d1.clearAuthoritative();
								d1.clearIP();
								position = d1.extractResponse(buf2);
								uca.close();
							} else if (d1.NS_list.size() > 0) {
								if (d1.isCNAME) {
									d1.isCNAME = false;
								}
								// else query for ip's
								UDPClient uca = new UDPClient(d1.NS_list.get(0));
								uca.send(tDnsBuffer, position);

								buf2 = uca.receive();
								d1.clearAdditional();
								d1.clearAuthoritative();
								d1.clearIP();
								position = d1.extractResponse(buf2);	
								uca.close();
							} else {
								if (d1.isCNAME) {
									uc.send(tDnsBuffer, position);
									d1.isCNAME = false;
									buf2 = null;
									buf2 = uc.receive();
									d1.clearAdditional();
									d1.clearAuthoritative();
									d1.clearIP();
									position = d1.extractResponse(buf2);
								} else {
									break;
								}
							}
							y++;
						}
					} catch (UnknownHostException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (SocketException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					//for now
					break;
				}

			}
			//}
		}
		// Send back response.
	}
}
