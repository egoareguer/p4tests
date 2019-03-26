/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define REGISTERS_SIZE 128 //Starting with a naive "Monitor EVERYTHING" approach
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
typedef bit<160> val_t;


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
	val_t val;
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

register<bit<160>>(REGISTERS_SIZE) t_reg; // Each port has a 160 bits slot which serves to write the features' bitmaps

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
		t_reg.read(meta.val, (bit<32>)hdr.tcp.dstPort); 
		hash(meta.h1, HashAlgorithm.crc32,
			16w0,
			{hdr.ipv4.dstAddr},
			16w31
		);
		hash(meta.h2, HashAlgorithm.crc32,
			16w0,
			{hdr.ipv4.srcAddr},
			16w31
		);
		hash(meta.h3, HashAlgorithm.crc32,
			16w0,
			{hdr.tcp.srcPort},
			16w31
		);
		hash(meta.h4, HashAlgorithm.crc32,
			16w0,
			{standard_metadata.packet_length},
			16w31
		);
    }
	
	// Shifts is limited to 8 bits on v1model, so we need to use something else, for example a table
	// Sadly, we still can't invoke tables within actions
	/*
	action set_dstIP() { 
		bit<160> tmp;
		tmp = 1 ;
		tmp = (tmp << meta.h1) / 2;
		meta.val = meta.val | tmp ; 
		t_reg.write((bit<32>)hdr.tcp.dstPort, meta.val);
	}
	action set_srcIP() {
		bit<160> tmp;
		tmp = 1 ;
		tmp = (tmp << meta.h2 + 31) ;
		meta.val = meta.val | tmp ; 
		t_reg.write((bit<32>)hdr.tcp.dstPort, meta.val);
	}
	action set_srcPort() {
		bit<160> tmp;
		tmp = 1 ;
		tmp = (tmp << meta.h3 + 63) ;
		meta.val = meta.val | tmp ; 
		t_reg.write((bit<32>)hdr.tcp.dstPort, meta.val);
	}
	action set_packetLength() {
		bit<160> tmp;
		tmp = 1 ;
		tmp = (tmp << meta.h4 + 95) ;
		meta.val = meta.val | tmp ; 
		t_reg.write((bit<32>)hdr.tcp.dstPort, meta.val);
	}
	*/
	action write_tmp( bit<160> var) {
		meta.val = meta.val | var ;
	}
	table dstIP_table {
		key = { meta.h1: exact; }
		actions = { drop; NoAction; write_tmp; }
		const entries = {
			#include "./tables/table0.txt"  
		}
		default_action = NoAction();
	}
	table srcIP_table {
		key = { meta.h2: exact; }
		actions = { drop; NoAction; write_tmp; }
		const entries = { 
			#include "./tables/table1.txt"  
		}
		default_action = NoAction();
	}
	table srcPort_table {
		key = { meta.h3: exact; }
		actions = { drop; NoAction; write_tmp; }
		const entries = { 
			#include "./tables/table2.txt"  
		}
		default_action = NoAction();
	}
	table pktLen_table {
		key = { meta.h2: exact; }
		actions = { drop; NoAction; write_tmp; }
		const entries = { 
			#include "./tables/table3.txt"  
		}
		default_action = NoAction();
	}
	
	//TODO: Missing: Counter SYN flags
	
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
	t_reg.write((bit<32>)hdr.tcp.dstPort, meta.val);
	/*
	set_dstIP();
	set_srcIP();
	set_srcPort();
	set_packetLength();
	*/
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
