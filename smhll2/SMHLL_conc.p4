/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#include "./variables/variables.p4"
//variables.p4 defines:
// 	>how many flow entries get HLL data structures allocated to them
//	>how wide said data structures are
//	>meta.index bit width to avoid entries block overlap

/* We want, aggregated by dst port, lightweight collection tables of the following features:
	#Unique src IPs
	#Unique dst IPs
	#Unique src Ports
	#Unique pkts sizes
	#Count of SYN pkts
	
	Cardinality is easiest obtained via loglog. 
*/

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

//Types used by HLL + SplitMerge
typedef bit<16> portBlock_t;
typedef bit<32> address_t;
typedef bit<32> hash_t;
typedef bit<56> remnant_t;
typedef bit<8>  index_t;
typedef bit<6>  short_byte_t;
typedef bit<8>  dumpFlag_t;

typedef bit<16> recirc_key_t;


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

header dumpBlock_t {
	//We assign those with bit slicing, which is limited to a 256 wide shift at once on this target
	bit<252> value0;
	bit<252> value1;
	bit<252> value2;
	bit<252> value3;
	bit<252> value4;
	bit<252> value5;
}

struct customMetadata_t {
	hash_t			hash;
	hash_t			hash2;
	index_t			index;
	remnant_t		remnant;
	short_byte_t	actual_zeroes;
	short_byte_t	seen_zeroes;
	address_t		address;
	portBlock_t		portBlock;
	recirc_key_t	recirc_key;
	bit<1>			returnFlag;	
	dumpFlag_t		dumpFlag;
	bit<1536>		dumpBlock;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t	 	 tcp;
	dumpBlock_t	 dumpBlock;
}

// register<bit<160>>(REGISTERS_SIZE) t_reg; // Each port has a 160 bits slot which serves to write the features' bitmaps
// In light of the reading problems past 2^63, we separate them for now
register<bit<6>>(NUM_N_FLOWS*NUM_HLL_REGISTERS) srcIP_masterReg;
register<bit<6>>(NUM_N_FLOWS*NUM_HLL_REGISTERS) dstIP_masterReg;
register<bit<6>>(NUM_N_FLOWS*NUM_HLL_REGISTERS) srcPort_masterReg;
register<bit<6>>(NUM_N_FLOWS*NUM_HLL_REGISTERS) pktLen_masterReg;
register<bit<32>>(2) syn_count_reg;


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
			0x90A: parse_dump;
			0x90B: parse_dump;
			0x90C: parse_dump;
			0x90D: parse_dump;
			0x90E: parse_dump;
			0x90F: parse_dump;
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
		transition accept; 
    }

	state parse_dump {
		packet.extract(hdr.ipv4);
		packet.extract(hdr.dumpBlock);
		transition accept;
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

	// ********************************************** //
	// ***************** HOOK CHECK  **************** //
	// ********************************************** //

	// Using the headers as a flag. Currently with hardcoded ethertype values

	// Uses the dumpFLag field in metan of type dumpFlag_t 
	// 090A -> flag value = 1 -> srcIP 
	// 090B -> flag value = 2 -> dstOP
	// 090C -> flag value = 3 -> srcPort
	// 090D -> flag value = 4 -> pktLen
	// 090E -> flag value = 5 -> syn
	// 090F -> flag value = 8 -> All
	// otherwise:			0 -> No dump

	action setDumpFlag(bit<8> value){
		meta.dumpFlag=value;
	}

	table hookCheck {
		key				= { hdr.ethernet.etherType : exact ; }
		actions			= { drop; NoAction; setDumpFlag; }
		default_action  = NoAction();
		const entries	= {
			0x090A: setDumpFlag(1);
			0x090B: setDumpFlag(2);
			0x090C: setDumpFlag(3);
			0x090D: setDumpFlag(4);
			0x090E: setDumpFlag(5);
			0x090F: setDumpFlag(8);
		}
	}

	// ********************************************** //
	// ***************** DUMP TABLE  **************** //
	// ********************************************** //

	// In essence, we read all entries of the matched portBlock port
	// Push them all one by one into hdr.portBlock values
	// Also set the egress port to reflect the packet where it came from

	action dump_srcIP(){
		bit<6> tmp;
		#include "./srcIP_portBlock_reads.txt"
	}
	action dump_dstIP(){
		bit<6> tmp;
		#include "./dstIP_portBlock_reads.txt"
	}
	action dump_srcPort(){
		bit<6> tmp;
		#include "./srcPort_portBlock_reads.txt"
	}
	action dump_pktLen(){
		bit<6> tmp;
		#include "./pktLen_portBlock_reads.txt"
	}
	action dump_syn(){
		bit<32> tmp;
		syn_count_reg.read(tmp,1);
		hdr.dumpBlock.value0[31:0]=tmp;
	}
	action dump_all(){
		bit<6> tmp;
//		#include "./all_portBlock_reads.txt"
	}

	table dumpTable {
		key				= { meta.dumpFlag: exact ; }
		actions			= { NoAction; dump_srcIP; dump_dstIP; dump_srcPort; dump_pktLen; dump_syn; dump_all ; }
		default_action  = NoAction();
		const entries	= {
			1: dump_srcIP();
			2: dump_dstIP();
			3: dump_srcPort();
			4: dump_pktLen();
			8: dump_all();
		}
	}

	// ********************************************** //
	// **************** SYN COUNTING **************** //
	// ********************************************** //

	action syn_count(){
	//uses: 
	//	syn_count_reg
	//	v1model's standard_metadata.instance_type
		bit<32> tmp;
		syn_count_reg.read(tmp, 1);
		syn_count_reg.write(1,tmp+1);
	}

	// ********************************************** //
	// ********** PortBlock match, dump ************* //
	// ********************************************** //

	action setPortBlock(bit<16> dstPort){
	// Uses bit<16> meta.portBlock
		meta.portBlock = dstPort;
	}

	table portBlock_table {
		key		= { hdr.tcp.dstPort: exact ; }
		actions = { drop; NoAction; setPortBlock; }
		size	= NUM_N_FLOWS ; 
	    default_action = NoAction();
		const entries = {
			#include "portBlock_entries.txt"
		}
	}	

	// ********************************************** //
    // *************** Initialization *************** //
	// ********************************************** //

	// Writes need compile constant references
    /* The actions which depend on depend on which feature is being processed are:
		>hashes
		>register reads
		>register writes
	*/
	// In this version, we just hardcode each stages to take place consecutively, without any recirculation


	// Hashing 
	// Actions are declared first as the table uses them
	action hash_srcIPzeroes() { 
	/* uses:
	     srcIP_masterReg
		 bit<32> meta.hash, meta.hash2
		 bit<8>  meta.index
		 bit<56> meta.remnant	 
		 bit<6>  meta.actual_zeroes
		 bit<32> meta.address
		 bit<8>  meta.portBlock
	*/
		hash(meta.hash,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 5w3, hdr.ipv4.srcAddr, 6w6 },
				32w0b11111111111111111111111111111111
		);
		hash(meta.hash2,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 3w5, hdr.ipv4.srcAddr, 7w10 },
				32w0b11111111111111111111111111111111
		);
		meta.index[INDEX_WIDTH:0]   = meta.hash[INDEX_WIDTH:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)NUM_HLL_REGISTERS*(bit<32>)meta.portBlock);
		srcIP_masterReg.read(meta.actual_zeroes, (bit<32>)meta.address);
	}

	action hash_dstIPzeroes() { 
	/* uses:
	     dstIP_masterReg
		 bit<32> meta.hash, meta.hash2
		 bit<8>  meta.index
		 bit<56> meta.remnant	 
		 bit<6>  meta.actual_zeroes
		 bit<32> meta.address
		 bit<8>  meta.portBlock
	*/
		hash(meta.hash,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 5w3, hdr.ipv4.dstAddr, 6w6 },
				32w0b11111111111111111111111111111111
		);
		hash(meta.hash2,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 3w5, hdr.ipv4.dstAddr, 7w10 },
				32w0b11111111111111111111111111111111
		);
		meta.index[INDEX_WIDTH:0]   = meta.hash[INDEX_WIDTH:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)NUM_HLL_REGISTERS*(bit<32>)meta.portBlock);
		dstIP_masterReg.read(meta.actual_zeroes, (bit<32>)meta.address);
	}
	action hash_srcPortZeroes() { 
	/* uses:
	     srcPort_masterReg
		 bit<32> meta.hash, meta.hash2
		 bit<8>  meta.index
		 bit<56> meta.remnant	 
		 bit<6>  meta.actual_zeroes
		 bit<32> meta.address
		 bit<8>  meta.portBlock
	 */
		hash(meta.hash,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 5w3, hdr.tcp.srcPort, 6w6 },
				32w0b11111111111111111111111111111111
		);
		hash(meta.hash2,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 3w5, hdr.tcp.srcPort, 7w10 },
				32w0b11111111111111111111111111111111
		);
		meta.index[INDEX_WIDTH:0]   = meta.hash[INDEX_WIDTH:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)NUM_HLL_REGISTERS*(bit<32>)meta.portBlock);
		srcPort_masterReg.read(meta.actual_zeroes, (bit<32>)meta.address);
	}

	action hash_pktLenZeroes() { 
	/* uses:
	     pktLen_masterReg
		 bit<32> meta.hash, meta.hash2
		 bit<8>  meta.index
		 bit<56> meta.remnant	 
		 bit<6>  meta.actual_zeroes
		 bit<32> meta.address
		 bit<8>  meta.portBlock
	 */
		hash(meta.hash,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 5w3, standard_metadata.packet_length, 6w6 },
				32w0b11111111111111111111111111111111
		);
		hash(meta.hash2,
				HashAlgorithm.crc32_custom,
				32w0,
				{ 3w5, standard_metadata.packet_length, 7w10 },
				32w0b11111111111111111111111111111111
		);
		meta.index[INDEX_WIDTH:0]   = meta.hash[INDEX_WIDTH:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)NUM_HLL_REGISTERS*(bit<32>)meta.portBlock);
		pktLen_masterReg.read(meta.actual_zeroes, (bit<32>)meta.address);
	}

	// ********************************************** //
        // *************** Counting Zeroes ************** //
	// ********************************************** //

	// One restrictions we need to fulfil is :
	// for a single pipeline runthrough, a given table
	// may be called _ONCE_
	// Therefore, to use is four times we need four instances of it

	action save_seenZeroes(short_byte_t value){
	// called by count_zeroes table
	// Uses: 
	//		bit<6> meta.seen_zeroes
		meta.seen_zeroes = value;
	}
	table count_zeroes1 {
	// Hardcoded table to count the zeroes for the srcIP register
	/* uses:
		bit<56> meta.remnant
		action write_srcIPzeroes
	*/
		key = { meta.remnant: lpm; }
		actions = {drop; NoAction; save_seenZeroes;} 
		size = 56;
		default_action = NoAction;
		const entries = {
			#include "./tables/table_56zeroes_lpm.txt"
		}
	}
	table count_zeroes2 {
	// Hardcoded table to count the zeroes for the srcIP register
	/* uses:
		bit<56> meta.remnant
		action write_srcIPzeroes
	*/
		key = { meta.remnant: lpm; }
		actions = {drop; NoAction; save_seenZeroes;} 
		size = 56;
		default_action = NoAction;
		const entries = {
			#include "./tables/table_56zeroes_lpm.txt"
		}
	}
	table count_zeroes3 {
	// Hardcoded table to count the zeroes for the srcIP register
	/* uses:
		bit<56> meta.remnant
		action write_srcIPzeroes
	*/
		key = { meta.remnant: lpm; }
		actions = {drop; NoAction; save_seenZeroes;} 
		size = 56;
		default_action = NoAction;
		const entries = {
			#include "./tables/table_56zeroes_lpm.txt"
		}
	}
	table count_zeroes4 {
	// Hardcoded table to count the zeroes for the srcIP register
	/* uses:
		bit<56> meta.remnant
		action write_srcIPzeroes
	*/
		key = { meta.remnant: lpm; }
		actions = {drop; NoAction; save_seenZeroes;} 
		size = 56;
		default_action = NoAction;
		const entries = {
			#include "./tables/table_56zeroes_lpm.txt"
		}
	}
	// Actions to push the highest value count with compile constant register references
	action write_srcIPzeroes(){
		srcIP_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}
	action write_dstIPzeroes(){
		dstIP_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}
	action write_srcPortZeroes(){
		srcPort_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}
	action write_pktLenZeroes(){
		pktLen_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}

	// ********************************************** //
	// ************* Ingress execution ************** //
	// ********************************************** //

	apply {
	//Reminder: conditionals aren't supported in actions on v1model

	// Hook check before counting anything
		hookCheck.apply();
		if (meta.dumpFlag!=0){
			dumpTable.apply();	
		}
		else{

		// SYN counting
			if (standard_metadata.instance_type==0){
				syn_count();
			}
		// PortBlock match
			portBlock_table.apply();
		// srcIP count processing
			hash_srcIPzeroes();
			count_zeroes1.apply();
			if (meta.seen_zeroes > meta.actual_zeroes) {
				write_srcIPzeroes();
			}
		// dstIP count processing
			hash_dstIPzeroes();
			count_zeroes2.apply();
			if (meta.seen_zeroes > meta.actual_zeroes) {
				write_dstIPzeroes();
			}
		// srcPort count processing
			hash_srcPortZeroes();
			count_zeroes3.apply();
			if (meta.seen_zeroes > meta.actual_zeroes) {
				write_srcPortZeroes();
			}
		// pktLen
			hash_pktLenZeroes();
			count_zeroes4.apply();
			if (meta.seen_zeroes > meta.actual_zeroes) {
				write_pktLenZeroes();
			}
		}
		if (hdr.ipv4.isValid()) {
			ipv4_lpm.apply();
		}
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout customMetadata_t meta,
                 inout standard_metadata_t standard_metadata) {
	action drop() {
        mark_to_drop();
    }	
	
	table dbug_table {
		key = { hdr.ethernet.dstAddr: exact;
				hdr.ipv4.srcAddr: exact; 
				hdr.ipv4.dstAddr: exact;
				hdr.tcp.srcPort: exact; 
				hdr.tcp.dstPort: exact;
				hdr.dumpBlock.value0[31:0]: exact; 
				hdr.dumpBlock.value1[31:0]: exact; 
				hdr.dumpBlock.value2[31:0]: exact; 
				hdr.dumpBlock.value3[31:0]: exact; 
				hdr.dumpBlock.value4[31:0]: exact; 
		}
		actions = { NoAction ; }
		default_action = NoAction();
	}

	action send_back(){
		bit<48> tmp;
		tmp=hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
		hdr.ethernet.srcAddr = tmp;
		standard_metadata.egress_spec = standard_metadata.ingress_port;
	}
    apply {
		send_back();
		dbug_table.apply();	
	}
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

control MyDeparser(packet_out packet, in headers hdr){ 
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	//We dump the portblock field if returnFlag was set
		packet.emit(hdr.dumpBlock);
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
