/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//This is hashpipe + an addition to dump everything when prompted by a packet with a reg_dump_t announced by a A010 ethertyp

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_REG_DUMP = 0xA0A0;
#define REGISTERS_SIZE 256

/* This is a modified solution/basic.p4 file from the p4lang tutorials. 
   The main idea is to include an elementary hashpipe structure to the overall pipeline. 
   Hashpipe's purpose is to track the top heavy hitters. To do this, it keeps a trace of (Key,Count) couples in d distinct tables, indexed by d distinct hash functions. 
   Furthermore, in order to avoid a second pass, it always insert the packet in the first table, and then keeps a rolling minimum as it looks up the current (Key,Count) in the remaining tables, evicting the lower count value.
   Hashpipe calls "stages" the distinct parts wherein a different hash function is used. 

 ***  Note that the paper's prototype code is available at *** 
   ***	https://github.com/vibhaa/hashpipe in p4v1_1.    ***

		And the paper itself at
 http://conferences.sigcomm.org/sosr/2017/papers/sosr17-heavy-hitter.pdf

In other words:
	Have d distinct hash functions. (We only use 2 in this program.)
	Instantiate a series d of tables of size N. There are actually two assorted tables for each hash: one to store the keys, one to store the count. Here they are registers called rKeysX, rValsX. 	For each packet:
	     Hash their key, in this case (srcIP, dsrIp, prot): index = hash(key) mod N. (There's no actual mod functions used, we just specify the hash shouldn't exceed a given bound).
	     if rVals1[index] == 0 : Plug (key,1) into rKeys,rVals at slot index, exit
	     if rKeys1[index] == key : add 1 to rVals1[index], exit
	     else: INSERT (key,1) into rKeys,rVals in slot index, save the previous couple into cKey,cVal. 
	This is "stage 1". The final insert is necessary so we don't lose automatically reject new bursty flows and still only do one treatment per packet.

	The second part of the algorithm consists in doing the same in the remaining stages (1 in this program) with the remaining hashes but with cKey,cVal as the carried along key,value pair to insert, with the difference that we will now only evict couples if their count is lower than cVal. Note that cVal may be greater than 1 now. 


// Further notes:	

	>What's missing is that we'd like more hash functions to use than those listed in v1model.p4.
	>The good news is we can use crc16 with a new parameter fed to it by the control plane to have the same hash function give different (hopefully independant) results. (I think.) Looking up "BMV2 Custom Hash functions" leads to the issue whereing Antonin mentions how bmv2 already has effectively "infinite" hash functions this way (although new custom ones would be good). 
	>Hashes can be put in the targets' source files otherwise (see behavioral-model/targets/simple_switch/simple_switch.cpp, look for hash_ex in the beginning.) Obviously that's for BMV2, so portability may suffer depending on the target.
	>We also would like not to have to hardcode how many stages there are. No idea how.
*/

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> key_t; //The keys used is dsrAddr++srcPort, so 48 bits
typedef bit<24> val_t; //Arbitrary bit count 
typedef bit<32> index_t;


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

header reg_dump_t {
	// Since we're using the switch as a middlebox, we'll assume MTU = 1500 bytes
	// We dumpt register pairs one at a time, recirculate it for a new turn every time
	bit<8> reg_num; //Which register do we dump? We'll have to use special tables to match on this
	bit<1> portion; //Difference between key dump and val dump
	bit<10000> payload;
}

struct customMetadata_t {
	index_t index1; 
	index_t index2;
	index_t index3;	
	key_t cKey; 
	key_t keyInTable; 
//
	val_t cVal;
	val_t valInTable;

	bit<1> match;
	bit<1> isRecirculate;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t	 tcp;
}

register<bit<48>>(REGISTERS_SIZE) rKeys1;
register<bit<48>>(REGISTERS_SIZE) rKeys2;
register<bit<48>>(REGISTERS_SIZE) rKeys3;
register<bit<24>>(REGISTERS_SIZE) rVals1;
register<bit<24>>(REGISTERS_SIZE) rVals2;
register<bit<24>>(REGISTERS_SIZE) rVals3;

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
			TYPE_REG_DUMP: parse_reg_dump;
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
	state parse_reg_dump {
		//Conditional are forbidden from parsers!
		packet.extract(hdr.ipv4);
		transition select(hdr.reg_dump.reg_num) {
			//Don't need to branch on reg num in the parser
			default; accept;
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
    // ***** Initialization actions set_key() & calculate_indexes *****
    action set_key() {
	meta.cKey[31:0] = hdr.ipv4.srcAddr;
	meta.cKey[47:32] = hdr.tcp.dstPort;	
    }
    action calculate_indexes() { //TODO check CRCs to make sure it verifies that they're parametered in a way that doesn't throw off the precision
	hash(meta.index1, HashAlgorithm.crc32, 
		32w0,
		{ 
		3w5,
		hdr.ipv4.srcAddr,
		7w10,
		hdr.tcp.dstPort
		},
		32w255 // troubleshooting: if on compilation, you get something like 
//simple_switch: ../../include/bm/bm_sim/stateful.h:117: const bm::Register& bm::RegisterArray::operator[](size_t) const: Assertion `idx < size()' failed
//It means the index was out of range, and this is probably where it'll need fixing
	);
	hash(meta.index2, HashAlgorithm.crc32, 
		64w0,
		{ 
		hdr.ipv4.srcAddr,
		5w3, 
		hdr.tcp.dstPort,
		6w6
		},
		32w255
	);
	hash(meta.index3, HashAlgorithm.crc32, 
		32w0,
		{ 
		8w42,
		hdr.ipv4.srcAddr,
		hdr.tcp.dstPort,
		4w0b1010
		},
		32w255
	);
    }

// ***** Hashpipe specific actions ***** //
// TODO: use parameters for the generic insert, increment, evict
// TODO: consider using includes, and making a script to automate writing them

// ***** Stage 1 actions ***** //
// Stage 1 is distinct because we always insert values into register1 
// as part of Hashpipe's "one pass per packet" design

    action insert1 () { //insert1 corresponds to an empty counter in register1
	rKeys1.write((bit<32>)meta.index1, meta.cKey);
	rVals1.write((bit<32>)meta.index1, 1 );
    }
    action increment1 () {  //used if we're processing the same key as in rKey1[index]
	rVals1.write((bit<32>)meta.index1, meta.valInTable+1); 
    }
    action swap1 () { //Used to force insertion into the first table and save the new minimums
	rKeys1.read(meta.keyInTable, meta.index1);
	rVals1.read(meta.valInTable, meta.index1);
	rKeys1.write((bit<32>)meta.index1, meta.cKey);
	rVals1.write((bit<32>)meta.index1, 1 ) ;
	meta.cKey=meta.keyInTable;
	meta.cVal=meta.valInTable;
    }

// ***** Stage 2 actions ***** //
// Stages 2+ are all the same save for the register pair used 
    action increment2 () { //rkeys2[index] == cKey
	rVals2.read(meta.valInTable, (bit<32>)meta.index2) ; 
	rVals2.write((bit<32>)meta.index2, meta.valInTable + meta.cVal ) ; 
    }
    action insert2() {	//nothing in rKeys2[index] yet
	rKeys2.write((bit<32>)meta.index2, meta.cKey ) ;
	rVals2.write((bit<32>)meta.index2, meta.cVal ) ;
    }
    action evict2() { //Evict the lower key,val of register2, swap it in cKey,cVal
	rKeys2.write((bit<32>)meta.index2, meta.cKey ) ;
	rVals2.write((bit<32>)meta.index2, meta.cVal ) ; 
	meta.cKey = meta.keyInTable ;
	meta.cVal = meta.valInTable ;
    }

// ***** Stage 3 actions ***** //
    action increment3 () { //rkeys3[index3] == cKey
	rVals3.read(meta.valInTable, (bit<32>)meta.index3); 
	rVals3.write((bit<32>)meta.index3, meta.valInTable + meta.cVal ) ; 
    }
    action insert3() {	//nothing in rKeys3[index3] yet
	rKeys3.write((bit<32>)meta.index3, meta.cKey ) ;
	rVals3.write((bit<32>)meta.index3, meta.cVal ) ;
    }
    action evict3() { //Evict the lower key,val of register3, swap it in cKey,cVal
	rKeys3.write((bit<32>)meta.index3, meta.cKey ) ;
	rVals3.write((bit<32>)meta.index3, meta.cVal ) ; 
	meta.cKey = meta.keyInTable ;
	meta.cVal = meta.valInTable ;

    }
    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid() ) { //We need both for the keys
            ipv4_lpm.apply(); //Just forward normally
        }

	//Initialization
	set_key();
	calculate_indexes();

	//Stage 1
	//Note that IFs in actions are unsupported
	rKeys1.read(meta.keyInTable, meta.index1);  
	rVals1.read(meta.valInTable, (bit<32>)meta.index1); 

	if (meta.valInTable == 0 ) { // Empty = Insertion 
		insert1(); exit ; 
	} 
	else if (meta.keyInTable == meta.cKey ) { //Same key = Incrementation
		increment1(); exit ;
	} else { //Insert in first register, by design
		swap1();
	}

	//Stage 2 Mostly the same
	rKeys2.read(meta.keyInTable, (bit<32>)meta.index2) ; 
	rVals2.read(meta.valInTable, (bit<32>)meta.index2);
	if (meta.cKey == meta.keyInTable ) { //Keys Match ! 
		increment2();
	}
	else if (meta.valInTable == 0 ) { //Empty slot 
		insert2();
	} 
	else if (meta.valInTable < meta.cVal ) { //Evict the lower count
		evict2();
	}

	//Stage 3
	rKeys3.read(meta.keyInTable, (bit<32>)meta.index3) ; 
	rVals3.read(meta.valInTable, (bit<32>)meta.index3);
	if (meta.cKey == meta.keyInTable ) { //Keys Match ! 
		increment2();
	}
	else if (meta.valInTable == 0 ) { //Empty slot 
		insert3();
	} 
	else if (meta.valInTable < meta.cVal ) { //Evict the lower count
		evict3();
	}
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
