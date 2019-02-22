/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> PRECISION_M = 0xFF; //Precision is arbitrarily 2^8 =256, meaning p = 8 
const bit<4> REGISTER_SIZE = 0x6; //6 bits is enough for up to 64, we won't have over 60 zeroes in a row in any hash anyway

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<64> hash_t;
typedef bit<56> remnant_t;
typedef bit<8> index_t;
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
    /* empty */
    hash_t hash;
    remnant_t remnant;
    index_t index; 
    index_t index_zeroes;
    key_t key;
    bool stop;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t 	 tcp;
}

register<bit<6>>(256) register1; //256 registers of size 6 are equivalent to a single one of size 256 whose slots are 6 bits

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
	transition accept ;
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
    }
	
    action zeroes() { //count the leading zeroes + 1 of meta.index (max 8) and push them in meta.index_zeroes
		      //TODO: FIXIT! Doing a while loop with hardcoded IFs is EXTREMELY HORRIBLE, but in the absence of loops, no choice. Parsers can loop- consider moving operation there? 
		      // Note: there is no avoiding doing as many accesses as there are zeroes.
		      // Important: does actually it hinder the performance? If no, it COULD be left here. Considering the structure is simple to write albeit repetitive, the addition of a script to write it could be considered acceptable then?

		      //It's a handwritten while loop using meta.stop == false as the stop condition. Yes, that's counter intuitive
		      // !!! Bit indexes must be compile time constants. !!!

	meta.stop = true ; meta.index_zeroes = 1 ;

	if (  ! (bool)meta.remnant[0:0]  ) { meta.stop = false ; } 
	if (  meta.stop ) {if((bool)meta.remnant[1:1] ) { meta.stop = false ; meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[2:2] ) { meta.stop = false ; meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[3:3] ) { meta.stop = false ; meta.index_zeroes = meta.index_zeroes + 1; } }	
	if (  meta.stop ) {if((bool)meta.remnant[4:4] ) { meta.stop = false ; meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[5:5] ) { meta.stop = false ; meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[6:6] ) { meta.stop = false ; meta.index_zeroes = meta.index_zeroes + 1; } }
	if (  meta.stop ) {if((bool)meta.remnant[7:7] ) { meta.stop = false ; meta.index_zeroes = meta.index_zeroes + 1; } }
	// ...And on, and on, and on, 56 times. A simple script would write this just fine given suitable tags
	register1.write((bit<32>)meta.index,(bit<6>) meta.index_zeroes);
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
