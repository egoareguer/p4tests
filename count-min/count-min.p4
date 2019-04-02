/* -*- P4_16 -*- */ 
#include <core.p4> 
#include <v1model.p4> 

const bit<16> TYPE_MYTUNNEL = 0x1212; 
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> MAX_TUNNEL_ID = 1 << 16;
const bit<32> MAX_HH_ID = 0 << 128;

//We use a counter to track how many hhs are in the stack
//Also we don't evict old ones or move the threshold, that's a limitation until we update the table on the fly

#define K_HH 128	//How many top flows we track
#define ROW_COUNT 256   //How many keys per register
#define HH_THRESHOLD 50 //How many hits until a key is considered a HH

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<24> count_t; //Up to 2^24~16M hits per key
typedef bit<48> key_t;   //KEY=DST IP &&& SRC PORT atm, so 48 bits
typedef bit<8> index_t;  //indexes go up to ROW_COUNT

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
	bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;	
}

struct metadata {//one index & one count per hash function we use. 3 in this program
	index_t index1;      	
	index_t index2;
	index_t index3;
	count_t current_min; 
	count_t count1;
	count_t count2;
	count_t count3;
	key_t key; 	    
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t 	 tcp;
}

register<bit<48>>(K_HH) hh_reg; //The first value is actually used to keep track of how full it is
register<bit<32>>(K_HH) ip_reg;
register<bit<16>>(K_HH) port_reg;
register<bit<24>>(ROW_COUNT) count_reg1;
register<bit<24>>(ROW_COUNT) count_reg2;
register<bit<24>>(ROW_COUNT) count_reg3;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
		6:	parse_tcp;
		default: accept; 
		}
    }
	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
	//TODO: find out why count3 stays empty

    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) { 
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

	action construct() { //calculate hashes, initializes meta.key and meta.current_min
		hash(meta.index1, HashAlgorithm.crc32,
			8w0,
			{3w5,hdr.ipv4.srcAddr,7w10,hdr.tcp.dstPort},
			8w255
		);
		hash(meta.index2, HashAlgorithm.crc32,
			8w0,
			{5w3,hdr.ipv4.srcAddr,7w60,hdr.tcp.dstPort},
			8w255
		);
		hash(meta.index3, HashAlgorithm.crc32,
			8w0,
			{8w42,hdr.ipv4.srcAddr,hdr.tcp.dstPort,4w0b1010},
			8w255
		);
		meta.current_min=0;
		meta.key[31:0] = hdr.ipv4.srcAddr;
		meta.key[47:32] = hdr.tcp.dstPort;
	}
	action reads() { //Reads all meta.countX values
		count_reg1.read(meta.count1, (bit<32>)meta.index1);
		count_reg2.read(meta.count2, (bit<32>)meta.index2);
		count_reg3.read(meta.count3, (bit<32>)meta.index3);
		meta.current_min=meta.count1;
	}
	action update() { //Non conservative update: simply increment each counter
		count_reg1.read(meta.current_min, (bit<32>)meta.index1);
		count_reg1.write((bit<32>)meta.index1, meta.current_min+1);
		count_reg2.read(meta.current_min, (bit<32>)meta.index2);
		count_reg2.write((bit<32>)meta.index2, meta.current_min+1);
		count_reg3.read(meta.current_min, (bit<32>)meta.index3);
		count_reg3.write((bit<32>)meta.index3, meta.current_min+1);
	}
	action update_1() {//Only increment the corresponding counter. The conservative update logic is in the main body of the control function
		count_reg1.write((bit<32>)meta.index1,meta.current_min+1);
	}
	action update_2() {
		count_reg2.write((bit<32>)meta.index2,meta.current_min+1);
	}
	action update_3() {
		count_reg3.write((bit<32>)meta.index3,meta.current_min+1);
	}

    table ipv4_lpm { //Standard ipv4 lpm matching
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
	
    apply {
        if (hdr.ipv4.isValid()) {
            // Process only non-tunneled IPv4 packets.
            ipv4_lpm.apply();
        }
		if (hdr.ipv4.isValid() && hdr.tcp.isValid()){ //i.e., we only apply the algorithm if we have an ipv4 packet with ipv4 & tcp fields available
			construct();
			//update.apply(); //Standard update, i.e increment every counter without second thought
			
			//Alternative: conservative update block
			/*Structure:    -> read counters 		
					-> calculate their min 
					-> increment those whose value == min
			*/
			reads();
			if(meta.count2 < meta.current_min) {
				meta.current_min=meta.count2;
			}
			if(meta.count3 < meta.current_min || meta.count3 == meta.current_min) {
				meta.current_min=meta.count3;
				update_3();
			}
			if(meta.count2 == meta.current_min ) {
				update_2();
			}
			if(meta.count1 == meta.current_min ) {
				update_1();
			}
			if(meta.current_min == HH_THRESHOLD) { // We only insert the first 255 hh to cross the threshold
							       // TODO: have an exponential decay/periodic resest joined to it
				
				//-> if the update pushed the min over HH_THRESHOLD, add key to hh_reg
				bit<48> tmp;
				hh_reg.read(tmp,(bit<32>)0);   
				if(tmp < K_HH) { //We check that we are not about to go out of range
					hh_reg.write((bit<32>)tmp+1,meta.key);  // hh_reg[tmp+1]=key of the new hh
					hh_reg.write((bit<32>)0, tmp+1); 	// hh_reg[0]++
					ip_reg.write((bit<32>)tmp+1,meta.key[31:0]);
					port_reg.write((bit<32>)tmp+1,meta.key[47:32]);
				}
			}
		}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
