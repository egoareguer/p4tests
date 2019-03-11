/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> PRECISION_M = 0xFF; //Precision is arbitrarily 2^8 =256, meaning p = 8 
const bit<4> REGISTER_SIZE = 0x6; //6 bits is enough for up to 64, we won't have over 60 zeroes in a row in any hash anyway

//reminders: BMV2 with v1model does not support register usage in parser
//	     Or conditional in actions themselves
//	     Bit indexes must be compile time constant

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<64> hash_t;
typedef bit<56> remnant_t;
typedef bit<8> index_t;
typedef bit<6> zeroes_t;
typedef bit<48> key_t; //key is currently just srcAddr++dstPort

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

struct metadata {
    hash_t hash;
    remnant_t remnant;
    index_t index; 
    index_t bit_index ;
    zeroes_t index_zeroes;
    zeroes_t actual_zeroes;
    key_t key;
    bool stop;
    bool last_zero;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t 	 tcp;
}

register<bit<6>>(256) register1; //256 registers of size 6 are equivalent to a single one of size 256 whose slots are 6 bits
				 //2^6=64, so we're good until 64 zeroes 

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
		6: parse_tcp;
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

/* No matter what, for each key, we'll 
	->hash the key 
	->get a fix on which registers it concerns
	->read and insert consecutive leading zeroes + 1 
   The rest of the algorithm is NOT our problem atm, the control plane handles it
   //Currently key = srcIP++dstPort
   //TODO: make the chosing of which keys are used parametric
*/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action initiate() {
	meta.key = hdr.ipv4.srcAddr++hdr.tcp.dstPort ;
	hash(meta.hash,
		HashAlgorithm.crc32_custom,
		64w0,
		{ hdr.ipv4.srcAddr, hdr.tcp.dstPort },
		64w0b1111111111111111111111111111111111111111111111111111111111111111 
	    );
	meta.index = meta.hash[7:0];
	meta.remnant = meta.hash[63:8]; 
	register1.read(meta.actual_zeroes, (bit<32>)meta.index);
    }
	
    action zeroes() { //count the leading zeroes + 1 of meta.index (max 8) and push them in meta.index_zeroes
		      //TODO: FIXIT! Doing a while loop with hardcoded IFs is EXTREMELY HORRIBLE, but in the absence of loops, no choice. Parsers can loop- consider moving operation there? 
			  //Solution: lpm match?
		      // !!! Bit indexes must be compile time constants. !!!

	meta.stop = true ; meta.index_zeroes = 1 ;

	if (  (bool)meta.remnant[0:0]  ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } 
	if (  meta.stop ) {if((bool)meta.remnant[1:1] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } } 
			   
	if (  meta.stop ) {if((bool)meta.remnant[2:2] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[3:3] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }	
	if (  meta.stop ) {if((bool)meta.remnant[4:4] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[5:5] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[6:6] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[7:7] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	// ...And on, and on, and on, 56 times. A simple script would write this just fine given suitable tags
/*	if (  meta.stop ) {if((bool)meta.remnant[8:8] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[9:9] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[10:10] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[11:11] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } } */
	if (  meta.stop ) {if((bool)meta.remnant[12:12] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[13:13] ) { meta.stop = false ; } else { meta.index_zeroes = meta.index_zeroes + 1; } } 

	//Problem: after a certain amount of if statements, compilation is far longer than it should be. Weird.
	//Second problem: far too few counts for 10k packets. Why?
    }
	action save_zeroes(zeroes_t value ) {
		meta.index_zeroes = value ;
	}
	table zeroes_lpm { //do a lpm match on remnant using pre-inserted table entries to determine what to write
			   //The counter helps determine whether we're close to the start/end
		key = { meta.remnant: lpm; }
		actions = {
			NoAction;
			drop;
			save_zeroes;
		}
		size = 57;
		default_action = NoAction;
		const entries = { //TODO find why he complains at #include
				//0x8000000/1  : save_zeroes(1);
				//0x4000000/2  : save_zeroes(2);
				//0x2000000/3  : save_zeroes(3);
				//0x1000000/4  : save_zeroes(4);
				(56w0b10000000000000000000000000000000000000000000000000000000/1) : save_zeroes(1);
				(56w0b01000000000000000000000000000000000000000000000000000000/2) : save_zeroes(2);
				(56w0b00100000000000000000000000000000000000000000000000000000/3) : save_zeroes(3);
				(56w0b00010000000000000000000000000000000000000000000000000000/4) : save_zeroes(4);
				(56w0b00001000000000000000000000000000000000000000000000000000/5) : save_zeroes(5);
				(56w0b00000100000000000000000000000000000000000000000000000000/6) : save_zeroes(6);
				(56w0b00000010000000000000000000000000000000000000000000000000/7) : save_zeroes(7);
				(56w0b00000001000000000000000000000000000000000000000000000000/8) : save_zeroes(8);
				(56w0b00000000100000000000000000000000000000000000000000000000/9) : save_zeroes(9);
				(56w0b00000000010000000000000000000000000000000000000000000000/10) : save_zeroes(10);
				(56w0b00000000001000000000000000000000000000000000000000000000/11) : save_zeroes(11);
				(56w0b00000000000100000000000000000000000000000000000000000000/12) : save_zeroes(12);
				(56w0b00000000000010000000000000000000000000000000000000000000/13) : save_zeroes(13);
				(56w0b00000000000001000000000000000000000000000000000000000000/14) : save_zeroes(14);
				(56w0b00000000000000100000000000000000000000000000000000000000/15) : save_zeroes(15);
				(56w0b00000000000000010000000000000000000000000000000000000000/16) : save_zeroes(16);
				(56w0b00000000000000001000000000000000000000000000000000000000/17) : save_zeroes(17);
				(56w0b00000000000000000100000000000000000000000000000000000000/18) : save_zeroes(18);
				(56w0b00000000000000000010000000000000000000000000000000000000/19) : save_zeroes(19);
				(56w0b00000000000000000001000000000000000000000000000000000000/20) : save_zeroes(20);
				(56w0b00000000000000000000100000000000000000000000000000000000/21) : save_zeroes(21);
				(56w0b00000000000000000000010000000000000000000000000000000000/22) : save_zeroes(22);
				(56w0b00000000000000000000001000000000000000000000000000000000/23) : save_zeroes(23);
				(56w0b00000000000000000000000100000000000000000000000000000000/24) : save_zeroes(24);
				(56w0b00000000000000000000000010000000000000000000000000000000/25) : save_zeroes(25);
				(56w0b00000000000000000000000001000000000000000000000000000000/26) : save_zeroes(26);
				(56w0b00000000000000000000000000100000000000000000000000000000/27) : save_zeroes(27);
				(56w0b00000000000000000000000000010000000000000000000000000000/28) : save_zeroes(28);
				(56w0b00000000000000000000000000001000000000000000000000000000/29) : save_zeroes(29);
				(56w0b00000000000000000000000000000100000000000000000000000000/30) : save_zeroes(30);
				(56w0b00000000000000000000000000000010000000000000000000000000/31) : save_zeroes(31);
				(56w0b00000000000000000000000000000001000000000000000000000000/32) : save_zeroes(32);
				(56w0b00000000000000000000000000000000100000000000000000000000/33) : save_zeroes(33);
				(56w0b00000000000000000000000000000000010000000000000000000000/34) : save_zeroes(34);
				(56w0b00000000000000000000000000000000001000000000000000000000/35) : save_zeroes(35);
				(56w0b00000000000000000000000000000000000100000000000000000000/36) : save_zeroes(36);
				(56w0b00000000000000000000000000000000000010000000000000000000/37) : save_zeroes(37);
				(56w0b00000000000000000000000000000000000001000000000000000000/38) : save_zeroes(38);
				(56w0b00000000000000000000000000000000000000100000000000000000/39) : save_zeroes(39);
				(56w0b00000000000000000000000000000000000000010000000000000000/40) : save_zeroes(40);
				(56w0b00000000000000000000000000000000000000001000000000000000/41) : save_zeroes(41);
				(56w0b00000000000000000000000000000000000000000100000000000000/42) : save_zeroes(42);
				(56w0b00000000000000000000000000000000000000000010000000000000/43) : save_zeroes(43);
				(56w0b00000000000000000000000000000000000000000001000000000000/44) : save_zeroes(44);
				(56w0b00000000000000000000000000000000000000000000100000000000/45) : save_zeroes(45);
				(56w0b00000000000000000000000000000000000000000000010000000000/46) : save_zeroes(46);
				(56w0b00000000000000000000000000000000000000000000001000000000/47) : save_zeroes(47);
				(56w0b00000000000000000000000000000000000000000000000100000000/48) : save_zeroes(48);
				(56w0b00000000000000000000000000000000000000000000000010000000/49) : save_zeroes(49);
				(56w0b00000000000000000000000000000000000000000000000001000000/50) : save_zeroes(50);
		/*		(56w0b00000000000000000000000000000000000000000000000000100000/51) : save_zeroes(51);
				(56w0b00000000000000000000000000000000000000000000000000010000/52) : save_zeroes(52);
				(56w0b00000000000000000000000000000000000000000000000000001000/53) : save_zeroes(53);
				(56w0b00000000000000000000000000000000000000000000000000000100/54) : save_zeroes(54);
				(56w0b00000000000000000000000000000000000000000000000000000010/55) : save_zeroes(55);
				(56w0b00000000000000000000000000000000000000000000000000000001/56) : save_zeroes(56);		
		*/
	}
    }
    
    action push_zeroes() {
	register1.write((bit<32>)meta.index, meta.index_zeroes ) ;	
    }
	    	
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
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
            ipv4_lpm.apply();
        }
	if (hdr.tcp.isValid()) {
	    initiate();
	    zeroes();   
	    if (meta.index_zeroes > meta.actual_zeroes ) {
		push_zeroes();
      	    }
	}
	zeroes_lpm.apply();
	if (meta.index_zeroes > meta.actual_zeroes ) {
		push_zeroes();
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






