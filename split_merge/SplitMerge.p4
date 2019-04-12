/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define REGISTERS_SIZE 256 //Starting with a naive "Monitor EVERYTHING" approach
			     // 12Mb / 64Kb ~ 200 bits, let's say 32bits per bitmap  
			     // -> 160bit entries in the register
			  

/* We want, aggregated by dst port, lightweight collection tables of the following features:
	#Unique src IPs
	#Unique dst IPs
	#Unique src Ports
	#Unique pkts sizes
	#Count of SYN pkts
	
	Cardinality is easiest obtained via loglog. 
		At low estimates, linear counting is used.
	However, we'll start with bitmaps to attempt a POC
	64=2^6 is the orders of magnitude of difference if we only check ports < 1024
*/

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> key_t; //The keys used is dsrAddr++srcPort, so 48 bits
typedef bit<16>  hash_t;
typedef bit<63> val_t;


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
	bit<4> dataOffset;
	bit<3> res;
	bit<3> ecn;
	bit<6> ctrl;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

struct customMetadata_t {
	val_t val1;
	val_t val2;
	val_t val3;
	val_t val4;
	hash_t h1;
	hash_t h2;	
	hash_t h3;
	hash_t h4;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t	 tcp;
}

// register<bit<160>>(REGISTERS_SIZE) t_reg; // Each port has a 160 bits slot which serves to write the features' bitmaps
// In light of the reading problems past 2^63, we separate them for now
register<bit<63>>(REGISTERS_SIZE) IPsrc_reg;
register<bit<63>>(REGISTERS_SIZE) IPdst_reg;
register<bit<63>>(REGISTERS_SIZE) Portsrc_reg;
register<bit<63>>(REGISTERS_SIZE) pktLength_reg;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout customMetadata_t meta,
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
		6:	 parse_tcp;
        	default: accept;
	}
    }

    state parse_tcp {
	packet.extract(hdr.tcp);
		transition accept; // No recirculate in hashpipe by design
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout customMetadata_t meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

//The control handles the decisions, no parameters are passed to the action atm.
//action ActionX corresponds to stageX. Obviously that's not sustainable for d higher than 2 and something to adress. //TODO

control MyIngress(inout headers hdr,
                  inout customMetadata_t meta,
                  inout standard_metadata_t standard_metadata
    ) {


    // ***** standard fare ipv4 forwarding *****
    action drop() {
        mark_to_drop();
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
    // ***** Initialization *****
    action calc_hashes() {
		IPsrc_reg.read(meta.val1, (bit<32>)hdr.tcp.dstPort);  // Silent crash here if dstPort > REGISTERS_SIZE
		IPdst_reg.read(meta.val2, (bit<32>)hdr.tcp.dstPort);
		Portsrc_reg.read(meta.val3, (bit<32>)hdr.tcp.dstPort);
		pktLength_reg.read(meta.val4, (bit<32>)hdr.tcp.dstPort);
		hash(meta.h1, HashAlgorithm.crc32,
			16w0,
			{hdr.ipv4.dstAddr},
			16w62
		);
		hash(meta.h2, HashAlgorithm.crc32,
			16w0,
			{hdr.ipv4.srcAddr},
			16w62
		);
		hash(meta.h3, HashAlgorithm.crc32,
			16w0,
			{hdr.tcp.srcPort},
			16w62
		);
		hash(meta.h4, HashAlgorithm.crc32,						// Busted. Is std's packet_length the cause?
			16w0,
			{standard_metadata.packet_length},
			16w62
		);
    }
	
	// Shifts is limited to 8 bits on v1model, so we need to use something else, here a table
	// Sadly, we still can't invoke tables within actions
	action write_tmp1( bit<63> var1) {
		meta.val1 = meta.val1 | var1 ;
	}
	action write_tmp2( bit<63> var2) {
		meta.val2 = meta.val2 | var2 ;
	}
	action write_tmp3( bit<63> var3) {
		meta.val3 = meta.val3 | var3 ;
	}
	action write_tmp4( bit<63> var4) {
		meta.val4 = meta.val4 | var4 ;
	}
	table dstIP_table {
		key = { meta.h1: exact; }
		actions = { drop; NoAction; write_tmp1; }
		const entries = {
			#include "./tables/table1_63.txt"  
		}
		default_action = NoAction();
	}
	table srcIP_table {
		key = { meta.h2: exact; }
		actions = { drop; NoAction; write_tmp2; }
		const entries = { 
			#include "./tables/table2_63.txt"  
		}
		default_action = NoAction();
	}
	table srcPort_table {
		key = { meta.h3: exact; }
		actions = { drop; NoAction; write_tmp3; }
		const entries = { 
			#include "./tables/table3_63.txt"  
		}
		default_action = NoAction();
	}
	table pktLen_table {
		key = { meta.h4: exact; }
		actions = { drop; NoAction; write_tmp4; }
		const entries = { 
			#include "./tables/table4_63.txt"  
		}
		default_action = NoAction();
	}
	
	//TODO: Missing: Count SYN flags
	
	//The control proper is pretty simple since we're just making records on top of forwarding packets
    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid() ) { //We need both for the keys
            ipv4_lpm.apply(); //Just forward normally
		}
	//Monitoring proper
	calc_hashes();
	
	dstIP_table.apply();
	srcIP_table.apply();
	srcPort_table.apply();
	pktLen_table.apply();
	IPsrc_reg.write((bit<32>)hdr.tcp.dstPort, meta.val1);
	IPdst_reg.write((bit<32>)hdr.tcp.dstPort, meta.val2);
	Portsrc_reg.write((bit<32>)hdr.tcp.dstPort, meta.val3);
	pktLength_reg.write((bit<32>)hdr.tcp.dstPort, meta.val4);
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout customMetadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout customMetadata_t meta) {
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
