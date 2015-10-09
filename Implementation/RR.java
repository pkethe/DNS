/* 
 * Resource records class, datastructure to store the details about
 * a record, Time to live(TTL). 
 * Time when to clear it from cache.
 */
class RR {
	int TTL;
	long removeAt;
	byte Record[];
	String hostName;
	int position;
	
	RR(String hostName, byte[] Record, int TTL, int position) {
		this.Record = Record;
		this.TTL = TTL;
		this.position = position;
		this.hostName = hostName;
	}
}
