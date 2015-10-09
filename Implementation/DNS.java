/* 
 * DNS.java 
 * 
 * Version: 
 *     $Id$ 1.1
 *     
 * @author	Pranav Sai Kethe
 * @author	Sandeep Kumar Ragila
 * 
 */

import java.util.ArrayList;

/**
 * The DNS class has methods for extracting DNSQuerys,
 * Building DNS Queries, building Responses.
 *
 */

public class DNS {
	// query
	short ID, QR;
	byte Opcode, AA, TC, RD, RA, Z, RCODE;
	short QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT;
	String QNAME;
	short QTYPE, QCLASS;
	int sizePosition = 0;

	// response
	short R_ID, R_QR;
	byte R_Opcode, R_AA, R_TC, R_RD, R_RA, R_Z, R_RCODE;
	short R_QDCOUNT, R_ANCOUNT, R_NSCOUNT, R_ARCOUNT;
	String R_QNAME;
	short R_QTYPE, R_QCLASS;
	int R_sizePosition = 0;	
	boolean isCNAME = false;

	ArrayList<String> NS_list;
	ArrayList<String> AA_list;
	ArrayList<String> IP_list;

	ArrayList<CNAME_RECORDS> cr;
	String authority;
	int startPointer;
	int endPointer;


	// Default Constructor
	DNS () {
		NS_list  = new ArrayList<String>();
		AA_list = new ArrayList<String>();
		IP_list = new ArrayList<String>();
		cr = new ArrayList<CNAME_RECORDS>();
		authority = new String();
	}


	// DNS layout
	/*    
	 * Method for extracting the query bytes.
	 *  	+---------------------+
			|        Header       |
		    +---------------------+
		    |       Question      | the question for the name server
		    +---------------------+
		    |        Answer       | RRs answering the question
		    +---------------------+
		    |      Authority      | RRs pointing toward an authority
		    +---------------------+
		    |      Additional     | RRs holding additional information
		    +---------------------+
	 */
	public void extractQuery(byte buffer[]) {	

		/*		Header section
		 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                      ID                       |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    QDCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    ANCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    NSCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    ARCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		 */
		// Extract the data
		// ID
		ID = (short)((buffer[0]&0xff) << 8|(buffer[1]&0xff));

		// QR, query-0, response-1 
		QR =  (byte) ((buffer[2]&0xff) >> 7);
		//System.out.println("QR->" + QR);

		// Opcode, standard query-0, inverse query-1, server status -2, reserved 3-15
		Opcode = (byte) ((buffer[2]&0xff)<<1);
		Opcode = (byte) ((Opcode&0xff)>>4);
		//System.out.println("Opcode->" + Opcode);

		// AA, only in responses
		AA = (byte) ((buffer[2]&0xff)<<5);
		AA = (byte) ((AA&0xff)>>7);
		//System.out.println("AA->" + AA);

		// TC, if truncation is needed
		TC = (byte) ((buffer[2]&0xff)<<6);
		TC = (byte) ((TC&0xff)>>7);
		//System.out.println("TC->" + TC);

		// RD, Recursion desired
		RD = (byte) ((buffer[2]&0xff)<<7);
		RD = (byte) ((RD&0xff)>>7);
		//System.out.println("RD->" + RD);

		// RA, Recursion available, in response
		RA = (byte) ((buffer[3]&0xff));
		RA = (byte) ((RA&0xff)>>7);
		//System.out.println("RA->" + RA);

		// Z, Reserved, must be 0
		Z = (byte) ((buffer[3]&0xff)<<1);
		Z = (byte) ((Z&0xff)>>5);

		// RCODE, Response code, No error - 0, Format error - 1, Server Failure -2...
		RCODE = (byte) ((buffer[3]&0xff)<<4);
		RCODE = (byte) ((RCODE&0xff)>>4);

		// QDCOUNT
		QDCOUNT = (short) ((buffer[4]&0xff)<<8 | (buffer[5]&0xff));
		//System.out.println("QDCOUNT->" + QDCOUNT);

		// ANCOUNT
		ANCOUNT = (short) ((buffer[6]&0xff)<<8 | (buffer[7]&0xff));
		//System.out.println("ANCOUNT->" + ANCOUNT);

		// NSCOUNT, Authority count
		NSCOUNT = (short) ((buffer[8]&0xff)<<8 | (buffer[9]&0xff));
		//System.out.println("NSCOUNT->" + NSCOUNT);

		// ARCOUNT, Additional count
		ARCOUNT = (short) ((buffer[10]&0xff)<<8 | (buffer[11]&0xff));
		//System.out.println("ARCOUNT->" + ARCOUNT);

		// Print Response
		sizePosition = 12;

		// not proper
		QNAME = "";
		while (true) {
			byte size = (byte)(buffer[sizePosition]&0xff);
			if (size == 0) {
				break;
			}
			sizePosition++;
			for (int i = 0; i < size; i++) {
				QNAME = QNAME + (char)buffer[sizePosition];
				sizePosition++;
			}

			QNAME = QNAME+ ".";
		}

		//System.out.println("QNAME->");
		// removing '.'
		if ((QNAME.length()> 0) && (QNAME.charAt(QNAME.length()-1) == '.')) {
			QNAME = QNAME.substring(0, QNAME.length()-1);
		}
		//System.out.println("QNAME->" + QNAME);
		sizePosition++;

		// QType
		QTYPE = (short) ((buffer[sizePosition]&0xff)<<8 | (buffer[sizePosition+1]&0xff));
		//System.out.println("QTYPE->" + QTYPE);

		sizePosition+=2;
		// QClass
		QCLASS = (short) ((buffer[sizePosition]&0xff)<<8 | (buffer[sizePosition+1]&0xff));
		//System.out.println("QCLASS->" + QCLASS);

		sizePosition +=2; // 2bytes
	}

	/* 
	 * Method to return the QNAME
	 */
	public String getQNAME() {
		return QNAME;
	}

	/* 
	 * Clear the authoritative server list.
	 */
	public void clearAuthoritative() {
		NS_list.clear();
	}
	
	/* 
	 * Clear the additional server list.
	 */
	
	public void clearAdditional() {
		AA_list.clear();
	}
	
	/* 
	 * Clear the answer section IP list.
	 */
	
	public void clearIP() {
		IP_list.clear();
	}
	
	
	/* 
	 * Method to extract response from pulbic domains
	 * 
	 * @param - 	buf
	 * 
	 * @return - 	position of the buffer.
	 */
	
	public int extractResponse(byte buf[]) {

		/*		Header section
		 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                      ID                       |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    QDCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    ANCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    NSCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			    |                    ARCOUNT                    |
			    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		 */
		// Extract the data
		// ID
		R_ID = (short)((buf[0]&0xff) << 8|(buf[1]&0xff));
		//System.out.println("ID" + ID);

		// QR, query-0, response-1 
		R_QR =  (byte) ((buf[2]&0xff) >> 7);
		//System.out.println("QR->" + QR);

		// Opcode, standard query-0, inverse query-1, server status -2, reserved 3-15
		R_Opcode = (byte) ((buf[2]&0xff)<<1);
		R_Opcode = (byte) ((R_Opcode&0xff)>>4);
		//System.out.println("Opcode->" + Opcode);

		// AA, only in responses
		R_AA = (byte) ((buf[2]&0xff)<<5);
		R_AA = (byte) ((R_AA&0xff)>>7);
		//System.out.println("AA->" + AA);

		// TC, if truncation is needed
		R_TC = (byte) ((buf[2]&0xff)<<6);
		R_TC = (byte) ((R_TC&0xff)>>7);
		//System.out.println("TC->" + TC);

		// RD, Recursion desired
		R_RD = (byte) ((buf[2]&0xff)<<7);
		R_RD = (byte) ((R_RD&0xff)>>7);
		//System.out.println("RD->" + RD);

		// RA, Recursion available, in response
		R_RA = (byte) ((buf[3]&0xff));
		R_RA = (byte) ((R_RA&0xff)>>7);
		//System.out.println("RA->" + RA);

		// Z, Reserved, must be 0
		R_Z = (byte) ((buf[3]&0xff)<<1);
		R_Z = (byte) ((R_Z&0xff)>>5);

		// RCODE, Response code, No error - 0, Format error - 1, Server Failure -2...
		R_RCODE = (byte) ((buf[3]&0xff)<<4);
		R_RCODE = (byte) ((R_RCODE&0xff)>>4);

		// QDCOUNT
		R_QDCOUNT = (short) ((buf[4]&0xff)<<8 | (buf[5]&0xff));
		//System.out.println("QDCOUNT->" + QDCOUNT);

		// ANCOUNT
		R_ANCOUNT = (short) ((buf[6]&0xff)<<8 | (buf[7]&0xff));

		// NSCOUNT, Authority count
		R_NSCOUNT = (short) ((buf[8]&0xff)<<8 | (buf[9]&0xff));
		//System.out.println("NSCOUNT->" + NSCOUNT);

		// ARCOUNT, Additional count
		R_ARCOUNT = (short) ((buf[10]&0xff)<<8 | (buf[11]&0xff));
		//System.out.println("ARCOUNT->" + ARCOUNT);

		// Print Response
		R_sizePosition = 12;

		// not proper
		R_QNAME = "";
		while (true) {
			byte size = (byte)(buf[R_sizePosition]&0xff);

			if (size == 0) {
				break;
			}
			R_sizePosition++;
			for (int i = 0; i < size; i++) {
				R_QNAME = R_QNAME + (char)buf[R_sizePosition];
				R_sizePosition++;
			}

			R_QNAME = R_QNAME+ ".";
		}

		//System.out.println("RQNAME" + R_QNAME);

		// removing '.'
		if ((R_QNAME.length()> 0)&&(R_QNAME.charAt(R_QNAME.length()-1) == '.')) {
			R_QNAME = R_QNAME.substring(0, R_QNAME.length()-1);
		}
		//System.out.println("R_QNAME" + R_QNAME);
		//System.out.println("QNAME->" + QNAME);
		R_sizePosition++;

		// QType
		R_QTYPE = (short) ((buf[R_sizePosition]&0xff)<<8 | (buf[R_sizePosition+1]&0xff));
		//System.out.println("QTYPE->" + QTYPE);

		R_sizePosition+=2;
		// QClass
		R_QCLASS = (short) ((buf[R_sizePosition]&0xff)<<8 | (buf[R_sizePosition+1]&0xff));
		//System.out.println("QCLASS->" + QCLASS);

		R_sizePosition +=2; // 2bytes

		if (R_ANCOUNT > 0) {
			int temp = 0;
			while (temp < R_ANCOUNT) {
				String a = "";

				CNAME_RECORDS cn = new CNAME_RECORDS();
				int pointer = R_sizePosition;
				boolean pathCompressed = false;
				while (true) {

					// check if end
					if ((int) (buf[pointer]&0xff) == 0) {
						break;

						// check if compression is there, if there, go till zero
					} else if ((int) (buf[pointer]&0xff) > 191) {
						//System.out.println("Path compressed");

						if (pathCompressed == false) { 
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						pathCompressed = true;
						pointer = (int) (buf[pointer]&0xff);
						// else, to till zero, while checking for compression.
					} else {


					}
					short size = (short)(buf[pointer]&0xff);
					for (int i = 0; i < size; i++) {
						if (pathCompressed == false) {
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						a = a + (char)buf[pointer];		
					}
					a = a+ ".";
					if (pathCompressed == false) {
						R_sizePosition++;
						pointer = R_sizePosition;
					} else {
						pointer++;
					}
				}
				// removing '.'
				if ((a.length()> 0)&&(a.charAt(a.length()-1) == '.')) {
					a = a.substring(0, a.length()-1);
				}
				cn.firstCol = a;
				//System.out.println("root->" + a);

				R_sizePosition+=1;
				// TYPE, 2 octets
				short R_TYPE = 0;
				R_TYPE = (short)((buf[R_sizePosition]&0xff) << 8|(buf[R_sizePosition+1]&0xff));
				//System.out.println("TYPE->" + R_TYPE);
				if (R_TYPE == 5) {
					//System.out.println("CNAME present" + R_TYPE + "RCOUNT" + R_ANCOUNT);
					isCNAME = true;
				}
				cn.QTYPE = R_TYPE;
				R_sizePosition+=2;

				// CLASS, 2octets
				short R_CLASS = 0;
				R_CLASS = (short)((buf[R_sizePosition]&0xff) << 8|(buf[R_sizePosition+1]&0xff));
				cn.QCLASS = R_CLASS;
				//System.out.println("CLASS->" + R_CLASS);
				R_sizePosition+=2;

				// TTL, 4 octets
				int R_TTL = 0;
				R_TTL = (int)((buf[R_sizePosition]&0xff)<<24|(buf[R_sizePosition+1]&0xff)<<16|(buf[R_sizePosition+2]&0xff) << 8|(buf[R_sizePosition+3]&0xff));
				//System.out.println("TTL->" + R_TTL);
				cn.TTL = R_TTL;
				R_sizePosition+=4;

				// RDLENGTH, 2 octets
				int R_RDLENGTH = 0;
				R_RDLENGTH = (int)((buf[R_sizePosition]&0xff) <<8 | (buf[R_sizePosition+1]&0xff));
				//System.out.println("RDLENGTH->" + R_RDLENGTH);
				R_sizePosition+=2;

				if (R_RDLENGTH ==4) {

					//RDATA
					a = (short)(buf[R_sizePosition]&0xff)+ "." + (short)(buf[R_sizePosition+1]&0xff) + "." + (short)(buf[R_sizePosition+2]&0xff) +"." + (short)(buf[R_sizePosition+3]&0xff);
					//System.out.println("IP->" + a);
					cn.IP[3] = buf[R_sizePosition+3];
					cn.IP[2] = buf[R_sizePosition+2];
					cn.IP[1] = buf[R_sizePosition+1];
					cn.IP[0] = buf[R_sizePosition+0];
					IP_list.add(new String(a));
					R_sizePosition+=4;	
				} else {
					// IPV6 or something else, skip for now
					a = "";
					pointer = R_sizePosition;
					pathCompressed = false;

					////System.out.printf("###0x%02X###", buf[pointer]);

					while (true) {
						//System.out.printf("###0x%02X###\n", buf[pointer]);

						// check if end
						if ((int) (buf[pointer]&0xff) == 0) {
							break;

							// check if compression is there, if there, go till zero
						} else if ((int) (buf[pointer]&0xff) > 191) {
							//System.out.println("Path compressed");
							if (pathCompressed == false) { 
								R_sizePosition++;
								pointer = R_sizePosition;
							} else {
								pointer++;
							}
							pathCompressed = true;
							pointer = (int) (buf[pointer]&0xff);
							// else, to till zero, while checking for compression.
						} else {


						}
						short size = (short)(buf[pointer]&0xff);
						for (int i = 0; i < size; i++) {
							if (pathCompressed == false) {
								R_sizePosition++;
								pointer = R_sizePosition;
							} else {
								pointer++;
							}
							a = a + (char)buf[pointer];
						}
						a = a+ ".";
						if (pathCompressed == false) {
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
					}
					// removing '.'
					if ((a.length()> 0) &&(a.charAt(a.length()-1) == '.')) {
						a = a.substring(0, a.length()-1);
					}
					//System.out.println("TLD->" + a);
					IP_list.add(new String(a));
					R_sizePosition+=1;		

					//R_sizePosition+=R_RDLENGTH;
				}
				if (isCNAME) {
					cn.secondCol = a;
					cr.add(cn);
					//System.out.println(cr.size());
				} else if ((cr.size() > 0) && (R_RDLENGTH ==4)) {

					cn.isIP = true;
					cr.add(cn);
					//System.out.println(cr.size());

				}
				temp++;

			}	
			// if QTYPE IS CNAME have to add few checks here
		} 

		// R_NSCOUNT and R_AACOUNT would be there
		if (R_NSCOUNT > 0) {
			// build an arrayList
			int temp = 0;
			startPointer = R_sizePosition;
			while (temp < R_NSCOUNT) {
				String a = "";

				int pointer = R_sizePosition;
				boolean pathCompressed = false;

				while (true) {
					//System.out.printf("0x%02X\n", buf[pointer]);

					// check if end
					if ((int) (buf[pointer]&0xff) == 0) {
						break;

						// check if compression is there, if there, go till zero
					} else if ((int) (buf[pointer]&0xff) > 191) {
						//System.out.println("Path compressed");
						if (pathCompressed == false) { 
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						pathCompressed = true;
						pointer = (int) (buf[pointer]&0xff);
						// else, to till zero, while checking for compression.
					} else {


					}
					short size = (short)(buf[pointer]&0xff);
					for (int i = 0; i < size; i++) {
						if (pathCompressed == false) {
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						a = a + (char)buf[pointer];		
					}
					a = a+ ".";
					if (pathCompressed == false) {
						R_sizePosition++;
						pointer = R_sizePosition;
					} else {
						pointer++;
					}
				}
				// removing '.'
				if ((a.length()> 0)&& (a.charAt(a.length()-1) == '.')) {
					a = a.substring(0, a.length()-1);
				}
				//System.out.println("root->" + a);
				authority = new String(a);

				R_sizePosition+=1;
				// TYPE, 2 octets
				short R_TYPE = 0;
				R_TYPE = (short)((buf[R_sizePosition]&0xff) << 8|(buf[R_sizePosition+1]&0xff));
				//System.out.println("TYPE->" + R_TYPE);
				R_sizePosition+=2;

				// CLASS, 2octets
				short R_CLASS = 0;
				R_CLASS = (short)((buf[R_sizePosition]&0xff) << 8|(buf[R_sizePosition+1]&0xff));
				//System.out.println("CLASS->" + R_CLASS);
				R_sizePosition+=2;

				// TTL, 4 octets
				int R_TTL = 0;
				R_TTL = (int)((buf[R_sizePosition]&0xff)<<24|(buf[R_sizePosition+1]&0xff)<<16|(buf[R_sizePosition+2]&0xff) << 8|(buf[R_sizePosition+3]&0xff));
				//System.out.println("TTL->" + R_TTL);
				R_sizePosition+=4;

				// RDLENGTH, 2 octets
				int R_RDLENGTH = 0;
				R_RDLENGTH = (int)((buf[R_sizePosition]&0xff) <<8 | (buf[R_sizePosition+1]&0xff));
				//System.out.println("RDLENGTH->" + R_RDLENGTH);
				R_sizePosition+=2;

				//RDATA
				a = "";
				pointer = R_sizePosition;
				pathCompressed = false;

				//System.out.printf("###0x%02X###", buf[pointer]);

				while (true) {
					//System.out.printf("###0x%02X###\n", buf[pointer]);

					// check if end
					if ((int) (buf[pointer]&0xff) == 0) {
						break;

						// check if compression is there, if there, go till zero
					} else if ((int) (buf[pointer]&0xff) > 191) {
						//System.out.println("Path compressed");
						if (pathCompressed == false) { 
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						pathCompressed = true;
						pointer = (int) (buf[pointer]&0xff);
						// else, to till zero, while checking for compression.
					} else {


					}
					short size = (short)(buf[pointer]&0xff);
					for (int i = 0; i < size; i++) {
						if (pathCompressed == false) {
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						a = a + (char)buf[pointer];
					}
					a = a+ ".";
					if (pathCompressed == false) {
						R_sizePosition++;
						pointer = R_sizePosition;
					} else {
						pointer++;
					}
				}
				// removing '.'
				if ((a.length()> 0)&&(a.charAt(a.length()-1) == '.')) {
					a = a.substring(0, a.length()-1);
				}
				//System.out.println("TLD->" + a);
				NS_list.add(new String(a));
				R_sizePosition+=1;		
				temp++;

			}	
		}
		if (R_ARCOUNT > 0) {
			//System.out.println("-------------ARCOUNT");
			// build an arrayList
			int temp = 0;
			while (temp < R_ARCOUNT) {
				String a = "";

				int pointer = R_sizePosition;
				boolean pathCompressed = false;

				while (true) {
					//System.out.printf("0x%02X\n", buf[pointer]);

					// check if end
					if ((int) (buf[pointer]&0xff) == 0) {
						break;

						// check if compression is there, if there, go till zero
					} else if ((int) (buf[pointer]&0xff) > 191) {
						//System.out.println("Path compressed");

						if (pathCompressed == false) { 
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						pathCompressed = true;
						pointer = (int) (buf[pointer]&0xff);
						// else, to till zero, while checking for compression.
					} else {


					}
					short size = (short)(buf[pointer]&0xff);
					for (int i = 0; i < size; i++) {
						if (pathCompressed == false) {
							R_sizePosition++;
							pointer = R_sizePosition;
						} else {
							pointer++;
						}
						try {
							a = a + (char)buf[pointer];
						} catch (Exception e) {
							System.out.println("aaa" + a);
						}
					}
					a = a+ ".";
					if (pathCompressed == false) {
						R_sizePosition++;
						pointer = R_sizePosition;
					} else {
						pointer++;
					}
				}
				// removing '.'
				if ((a.length()> 0) &&(a.charAt(a.length()-1) == '.')) {
					a = a.substring(0, a.length()-1);
				}
				//System.out.println("root->" + a);

				R_sizePosition+=1;
				// TYPE, 2 octets
				short R_TYPE = 0;
				R_TYPE = (short)((buf[R_sizePosition]&0xff) << 8|(buf[R_sizePosition+1]&0xff));
				//System.out.println("TYPE->" + R_TYPE);
				R_sizePosition+=2;

				// CLASS, 2octets
				short R_CLASS = 0;
				R_CLASS = (short)((buf[R_sizePosition]&0xff) << 8|(buf[R_sizePosition+1]&0xff));
				//System.out.println("CLASS->" + R_CLASS);
				R_sizePosition+=2;

				// TTL, 4 octets
				int R_TTL = 0;
				R_TTL = (int)((buf[R_sizePosition]&0xff)<<24|(buf[R_sizePosition+1]&0xff)<<16|(buf[R_sizePosition+2]&0xff) << 8|(buf[R_sizePosition+3]&0xff));
				//System.out.println("TTL->" + R_TTL);
				R_sizePosition+=4;

				// RDLENGTH, 2 octets
				int R_RDLENGTH = 0;
				R_RDLENGTH = (int)((buf[R_sizePosition]&0xff) <<8 | (buf[R_sizePosition+1]&0xff));
				//System.out.println("RDLENGTH->" + R_RDLENGTH);
				R_sizePosition+=2;

				if (R_RDLENGTH ==4) {

					//RDATA
					a = (short)(buf[R_sizePosition]&0xff)+ "." + (short)(buf[R_sizePosition+1]&0xff) + "." + (short)(buf[R_sizePosition+2]&0xff) +"." + (short)(buf[R_sizePosition+3]&0xff);
					//System.out.println("IP->" + a);
					AA_list.add(new String(a));
					R_sizePosition+=4;	
				} else {
					// IPV6 or something else, skip for now
					R_sizePosition+=R_RDLENGTH;
				}
				temp++;

			}	

		}
		endPointer = R_sizePosition;
		return R_sizePosition;
	}

	/* 
	 * Build Query to be sent to the public domain
	 * 
	 * @param - 	buf
	 * 
	 * @return - 	position of the buffer.
	 */
	
	public int buildQuery(byte buf[]) {
		//System.out.println("--->" +QNAME);
		clearBytes(buf, buf.length);
		buf[1] = (byte)(ID & 0xff);
		buf[0] = (byte)((ID >> 8) & 0xff);
		// QR, query-0, response-1 
		buf[2] = (byte) (buf[2]|QR<<7);

		// Opcode, standard query-0, inverse query-1, server status -2, reserved 3-15
		buf[2] = (byte) (buf[2]|Opcode<<3);

		// AA, only in responses
		buf[2] = (byte) (buf[2]|AA<<2);

		// TC, if truncation is needed
		buf[2] = (byte) (buf[2]|TC<<1);

		// RD, Recursion desired, we want it know recursively
		//buf[2] = (byte) ((buf[2]&0xff)|RD);
		buf[2] = 0;
		//System.out.printf("0x%02X ", buf[2]);

		// RA, Recursion available, in response
		buf[3] = (byte) (buf[3]|RA<<7);

		// Z, Reserved, must be 0
		buf[3] = (byte) (buf[3]|Z<<4);

		// RCODE, Response code, No error - 0, Format error - 1, Server Failure -2...
		buf[3] = (byte) (buf[3]|RCODE);

		// QDCOUNT
		buf[5] = (byte) (QDCOUNT);
		buf[4] = (byte) (QDCOUNT>>8);

		// ANCOUNT
		buf[7] = (byte) (ANCOUNT);
		buf[6] = (byte) (ANCOUNT>>8);

		// NSCOUNT, Authority count
		buf[9] = (byte) (NSCOUNT);
		buf[8] = (byte) (NSCOUNT>>8);

		// ARCOUNT, Additional count
		buf[11] = (byte) (ARCOUNT);
		buf[10] = (byte) (ARCOUNT>>8);

		/* 	Question Section
		 *	0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                                               |
		    /                     QNAME                     /
		    /                                               /
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                     QTYPE                     |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                     QCLASS                    |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		 */

		String tokens[] = QNAME.split("\\.");
		//System.out.println("--->" +QNAME);

		sizePosition = 12;
		for(int i = 0; i < tokens.length; i++) {
			short size;
			size = (short) tokens[i].length(); 
			buf[sizePosition] = (byte)(size);
			sizePosition++;
			for ( int j = 0; j < tokens[i].length(); j++) {
				char c = tokens[i].charAt(j);
				buf[sizePosition] = (byte) c;
				sizePosition++;
			}	
		}
		sizePosition++;
		// QTYPE, queue type
		buf[sizePosition+1] = (byte) (QTYPE&0xff);
		buf[sizePosition] = (byte) ((QTYPE>>8)&0xff);

		sizePosition +=2; // 2bytes

		// QCLASS, queue class, IN
		buf[sizePosition+1] = (byte) (QCLASS);
		buf[sizePosition] = (byte) (QCLASS>>8);

		sizePosition +=2; //2bytes
		return sizePosition;
	}	

	/* 
	 * Method to build Response which has to be sent back to the client.
	 * 
	 * @param - 	buf
	 * 
	 * @param - 	QNAME previous
	 * 
	 * @return - 	buffer pointer.
	 */
	
	public byte[] buildResponse(byte buffer[], String oldName) {
		byte newBuffer[] = new byte[512];
		clearBytes(newBuffer, 512);

		newBuffer[1] = (byte)(ID & 0xff);
		newBuffer[0] = (byte)((ID >> 8) & 0xff);
		// QR, query-0, response-1 
		byte QR = 1;
		newBuffer[2] = (byte) (((QR<<7)&0xff)|newBuffer[2]);

		// Opcode, standard query-0, inverse query-1, server status -2, reserved 3-15
		byte Opcode = 0;
		newBuffer[2] = (byte) (newBuffer[2]|Opcode<<3);

		// AA, only in responses
		byte AA = 0;
		newBuffer[2] = (byte) (newBuffer[2]|AA<<2);

		// TC, if truncation is needed
		byte TC = 0;
		newBuffer[2] = (byte) (newBuffer[2]|TC<<1);

		// RD, Recursion desired, we want it know recursively
		byte RD = 1;
		newBuffer[2] = (byte) ((RD&0xff)|newBuffer[2]);
		//System.out.printf("0x%02X ", newBuffer[2]);

		// RA, Recursion available, in response
		byte RA = 1;
		newBuffer[3] = (byte) (((RA<<7)&0xff)|newBuffer[3]);

		// Z, Reserved, must be 0
		byte Z = 0;
		newBuffer[3] = (byte) (newBuffer[3]|Z<<4);

		// RCODE, Response code, No error - 0, Format error - 1, Server Failure -2...
		byte RCODE = 0;
		newBuffer[3] = (byte) (newBuffer[3]|RCODE);

		// QDCOUNT
		short QDCOUNT = 1;
		newBuffer[5] = (byte) (QDCOUNT);
		newBuffer[4] = (byte) (QDCOUNT>>8);

		// ANCOUNT
		short ANCOUNT = (short)cr.size();
		newBuffer[7] = (byte) (ANCOUNT);
		newBuffer[6] = (byte) (ANCOUNT>>8);

		// NSCOUNT, Authority count
		short NSCOUNT = 0;
		newBuffer[9] = (byte) (NSCOUNT);
		newBuffer[8] = (byte) (NSCOUNT>>8);

		// ARCOUNT, Additional count
		short ARCOUNT = 0;
		newBuffer[11] = (byte) (ARCOUNT);
		newBuffer[10] = (byte) (ARCOUNT>>8);

		/* 	Question Section
		 *	0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                                               |
		    /                     QNAME                     /
		    /                                               /
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                     QTYPE                     |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                     QCLASS                    |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		 */

		String tokens[] = oldName.split("\\.");
		//System.out.println("--->" +QNAME);

		int sizePosition = 12;
		for(int i = 0; i < tokens.length; i++) {
			short size;
			size = (short) tokens[i].length(); 
			newBuffer[sizePosition] = (byte)(size);
			sizePosition++;
			for ( int j = 0; j < tokens[i].length(); j++) {
				char c = tokens[i].charAt(j);
				newBuffer[sizePosition] = (byte) c;
				sizePosition++;
			}	
		}
		sizePosition++;

		// QTYPE, queue type
		short QTYPE = 1;
		newBuffer[sizePosition+1] = (byte) (QTYPE);
		newBuffer[sizePosition] = (byte) (QTYPE>>8);

		sizePosition +=2; // 2bytes

		// QCLASS, queue class, IN
		short QCLASS = 1;
		newBuffer[sizePosition+1] = (byte) (QCLASS);
		newBuffer[sizePosition] = (byte) (QCLASS>>8);

		sizePosition +=2; //2bytes

		// Fill Answer Section
		sizePosition = fillAnswerSection(newBuffer, sizePosition);

		endPointer = sizePosition;

		return newBuffer;
	}

	/* 
	 * Fills the answer section while building response.
	 * 
	 * @param - 	buf
	 * 
	 * @param - 	size position
	 * 
	 * @return - 	pointer to the position.
	 */
	
	int fillAnswerSection(byte buffer[], int sizePosition) {
		int index = 0;
		while (index < cr.size()) {
			try {
				String tokens[] = cr.get(index).firstCol.split("\\.");

				for(int i = 0; i < tokens.length; i++) {
					short size;
					size = (short) tokens[i].length(); 

					buffer[sizePosition] = (byte)(size);

					sizePosition++;
					for ( int j = 0; j < tokens[i].length(); j++) {
						char c = tokens[i].charAt(j);
						buffer[sizePosition] = (byte) c;
						sizePosition++;
					}	
				}

				sizePosition++;
				buffer[sizePosition+1] = (byte) (cr.get(index).QTYPE);
				buffer[sizePosition] = (byte) (cr.get(index).QTYPE>>8);
				sizePosition+=2;

				buffer[sizePosition+1] = (byte) (cr.get(index).QCLASS);
				buffer[sizePosition] = (byte) (cr.get(index).QCLASS>>8);
				sizePosition+=2;

				buffer[sizePosition+3] = (byte) (cr.get(index).TTL);
				buffer[sizePosition+2] = (byte) (cr.get(index).TTL>>8);
				buffer[sizePosition+1] = (byte) (cr.get(index).TTL>>16);
				buffer[sizePosition] = (byte) (cr.get(index).TTL>>24);
				sizePosition+=4;

				tokens = cr.get(index).secondCol.split("\\.");

				short rlen = 1;
				if (cr.get(index).isIP) {
					rlen = 4;
					buffer[sizePosition+1] = (byte)(rlen & 0xff);
					buffer[sizePosition] = (byte)((rlen >> 8) & 0xff);	
					sizePosition+=2;

					buffer[sizePosition+3] = cr.get(index).IP[3];
					buffer[sizePosition+2] = cr.get(index).IP[2];
					buffer[sizePosition+1] = cr.get(index).IP[1];
					buffer[sizePosition] = cr.get(index).IP[0];
					sizePosition+=4;

				} else {

					for (int i = 0; i < tokens.length; i++) {
						rlen += tokens[i].length();
						rlen++;
					}
					buffer[sizePosition+1] = (byte)(rlen & 0xff);
					buffer[sizePosition] = (byte)((rlen >> 8) & 0xff);		

					sizePosition+=2;

					for(int i = 0; i < tokens.length; i++) {
						short size;
						size = (short) tokens[i].length(); 
						buffer[sizePosition] = (byte)(size);
						sizePosition++;
						for ( int j = 0; j < tokens[i].length(); j++) {
							char c = tokens[i].charAt(j);
							buffer[sizePosition] = (byte) c;
							sizePosition++;
						}	
					}
					sizePosition++;
				}
				index++;
			} catch (Exception e) {
				System.out.print("");
			}
		}
		return sizePosition;
	}
	
	/* 
	 * Clear bytes
	 * 
	 * @param - 	array[]
	 * 
	 * @param - 	size 
	 * 
	 */
	
	void clearBytes(byte array[], int size) {
		for (int i = 0; i < size; i++) {
			array[i] = 0;
		}
	}

	/* 
	 * Internal class to maintain the responses in the cache.
	 * 
	 */
	
	class CNAME_RECORDS {
		public boolean isIP;
		String firstCol, secondCol;
		short QTYPE;
		int TTL;
		short QCLASS;
		int size;
		byte IP[];

		public CNAME_RECORDS() {
			firstCol = new String();
			secondCol = new String();
			QTYPE = 0;
			TTL = 0;
			QCLASS = 0;
			isIP = false;
			IP = new byte[4];
		}
		@Override
		public String toString() {
			// TODO Auto-generated method stub
			return super.toString();
		} 
	}
}
