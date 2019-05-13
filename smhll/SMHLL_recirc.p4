/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//taking SplitMerge, using HLL's data structure for ONE feature (IPsrc)

const bit<16> TYPE_IPV4 = 0x800;
#define REGISTERS_SIZE 256 //Starting with a naive "Monitor EVERYTHING" approach
			     // 12Mb / 64Kb ~ 200 bits, let's say 32bits per bitmap  
			     // -> 160bit entries in the register

#define NUM_HLL_REGISTERS 256 //Directly correlates to HLL's error estimation
#define NUM_K_FLOWS 256 //How many flows we'll have kept
			  

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

//Types used by HLL + SplitMerge
typedef bit<8>  portBlock_t;
typedef bit<32> address_t;
typedef bit<32> hash_t;
typedef bit<56> remnant_t;
typedef bit<8>  index_t;
typedef bit<6>  short_byte_t;

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

struct customMetadata_t {
	hash_t hash;
	hash_t hash2;
	index_t index;
	remnant_t remnant;
	short_byte_t actual_zeroes;
	short_byte_t seen_zeroes;
	address_t address;
	portBlock_t portBlock;
	recirc_key_t recirc_key;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t	 tcp;
}

// register<bit<160>>(REGISTERS_SIZE) t_reg; // Each port has a 160 bits slot which serves to write the features' bitmaps
// In light of the reading problems past 2^63, we separate them for now
register<bit<6>>(REGISTERS_SIZE*NUM_HLL_REGISTERS) IPsrc_masterReg;
register<bit<6>>(REGISTERS_SIZE*NUM_HLL_REGISTERS) IPdst_masterReg;
register<bit<6>>(REGISTERS_SIZE*NUM_HLL_REGISTERS) srcPort_masterReg;
register<bit<6>>(REGISTERS_SIZE*NUM_HLL_REGISTERS) pktLen_masterReg;
register<bit<32>>(1) syn_count_reg;


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


	// ********************************************** //
	// **************** SYN COUNTING **************** //
	// ********************************************** //

	action syn_count(){
	//uses: 
	//	syn_count_reg
	//	v1model's standard_metadata.instance_type
		bit<32> tmp;
		syn_count_reg.read(tmp, 0);
		syn_count_reg.write(0,tmp+1);
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
	// They need a branching, either through IFs or a table
	// We use a table
	// Said table match on a flag in the header. 
	// THIS IMPLIES USING THIS PROGRAM IN A DEDICATED MIDDLEBLOX ENVIRONMENT



	// Hashing 
	// Actions are declared first as the table uses them
	action hash_srcIPzeroes() { 
	/* uses:
	     IPsrc_masterReg
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
		meta.index   = meta.hash[7:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)256*(bit<32>)meta.portBlock);
		IPsrc_masterReg.read(meta.actual_zeroes, (bit<32>)meta.address);
	}

	action hash_dstIPzeroes() { 
	/* uses:
	     IPdst_masterReg
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
		meta.index   = meta.hash[7:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)256*(bit<32>)meta.portBlock);
		IPsrc_masterReg.read(meta.actual_zeroes, (bit<32>)meta.address);
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
		meta.index   = meta.hash[7:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)256*(bit<32>)meta.portBlock);
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
		meta.index   = meta.hash[7:0];
		meta.remnant = meta.hash2++meta.hash[31:8];
		meta.address = (bit<32>)meta.index+((bit<32>)256*(bit<32>)meta.portBlock);
		pktLen_masterReg.read(meta.actual_zeroes, (bit<32>)meta.address);
	}
	table hash_zeroes  {
		key = { hdr.ethernet.etherType : exact; }
		actions = { 
		drop; 
		NoAction; 
		hash_srcIPzeroes; 
		hash_dstIPzeroes;
		hash_srcPortZeroes;
		hash_pktLenZeroes;
		}
		default_action = drop;
		const entries = {
			0x0800 : hash_srcIPzeroes();
			0x08AB : hash_dstIPzeroes();
			0x08AC : hash_srcPortZeroes();
			0x08AD : hash_pktLenZeroes();
		}
	}
	

	// ********************************************** //
    // *************** Counting Zeroes ************** //
	// ********************************************** //

	action save_seenZeroes(short_byte_t value){
	// called by count_zeroes table
	// Uses: 
	//		bit<6> meta.seen_zeroes
		meta.seen_zeroes = value;
	}
	table count_zeroes {
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
		IPsrc_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}
	action write_dstIPzeroes(){
		IPdst_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}
	action write_srcPortZeroes(){
		srcPort_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}
	action write_pktLenZeroes(){
		pktLen_masterReg.write((bit<32>)meta.address, meta.seen_zeroes);
	}
	table push_zeroes  {
		key = { hdr.ethernet.etherType : exact; }
		actions = { 
		drop; 
		NoAction; 
		write_srcIPzeroes; 
		write_dstIPzeroes;
		write_srcPortZeroes;
		write_pktLenZeroes;
		}
		default_action = drop;
		const entries = {
			0x0800 : write_srcIPzeroes();
			0x08AB : write_dstIPzeroes();
			0x08AC : write_srcPortZeroes();
			0x08AD : write_pktLenZeroes();
		}
	}

	// ********************************************** //
	// ************* Ingress execution ************** //
	// ********************************************** //

	apply {
	//Reminder: conditionals aren't supported in actions on v1model
		if (standard_metadata.instance_type==0){
			syn_count();
		}
		hash_zeroes.apply();
		count_zeroes.apply();
		if (meta.seen_zeroes > meta.actual_zeroes) {
			push_zeroes.apply();
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
	action recirc(recirc_key_t k){
		hdr.ethernet.etherType = k;
		recirculate(standard_metadata);
	}
	table recirc_table {
		actions = { drop; NoAction; recirc; }
		key = { hdr.ethernet.etherType : exact; }
		size = 3;
		default_action = drop;
		const entries = {
			0x0800 : recirc(0x08AB);
			0x08AB : recirc(0x08AC); 
			0X08AC : recirc(0x08AD);
		}
	}
    apply {
		recirc_table.apply();
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
