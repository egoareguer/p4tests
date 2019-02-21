/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/* This is a modified solution/basic.p4 file from the p4lang tutorials. 
   The main idea is to include an elementary hashpipe structure to the overall pipeline. 
   Hashpipe's purpose is to track the top heavy hitters. To do this, it keeps a trace of (Key,Count) couples in d distinct tables, indexed by d distinct hash functions. 
   Furthermore, in order to avoid a second pass, it always insert the packet in the first table, and then keeps a rolling minimum as it looks up the current (Key,Count) in the remaining tables, evicting the lower count value.
   Hashpipe calls "stages" the distinct parts wherein a different hash function is used. 

 ***  Note that the paper's prototype code is available at *** 
   ***	https://github.com/vibhaa/hashpipe in p4v1_1.    ***

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
typedef bit<72> key_t; //The keys used is dsrAddr++srcAddr++protocol, so 72 bits
typedef bit<24> val_t; //Arbitrary bit count 

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

struct metadata {
	key_t cKey; //cKey & cVal stand for Current Key & Current Val. They are used for the rolling minimum values.
	val_t cVal;
	key_t keyInTable; //Used to read the values actually in the table, and to swap them without losing them
	val_t valInTable; 
	key_t index; //Used to store the hash value.
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

register<bit<72>>(100) rKeys1; //72 bits for srcAddr++dstAddr+protocol. 
register<bit<24>>(100) rVals1; //TODO: don't hardcode what they keys are
register<bit<72>>(100) rKeys2; //100 is an arbitrary value. 
register<bit<24>>(100) rVals2;

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
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

extern Checksum1 { //Useless at the moment, ignore
	Checksum1();
	void clear();
	void update<T>(in T data);
	void remove<T>(in T data);
	bit<32> get();
	bit<32> compute(inout headers hdr, inout metadata meta, out key_t ket);
}
extern Checksum2 {
	Checksum2();
	void clear();
	void update<T>(in T data);
	void remove<T>(in T data);
	bit<32> get();
}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

//The control handles the decisions, no parameters are passed to the action atm.
//action ActionX corresponds to stageX. Obviously that's not sustainable for d higher than 2 and something to adress. //TODO

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata
       ) {

    action do_stage1() { //Useless, the target doesn't like conditional actions in Actions
	
	    }

    action do_stage2(){
	
    }

    action drop() {
        mark_to_drop();
    }
    action insert1 () { //TODO: change it so it takes a register ref in parameter instead of spelling them out
			//insert1 corresponds to finding the no saved value for the given key
	rKeys1.write((bit<32>)meta.index, hdr.ipv4.dstAddr++hdr.ipv4.srcAddr++hdr.ipv4.protocol) ;
	rVals1.write((bit<32>)meta.index, 1 ) ;
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

    table track_stage1 { //They're called track_stageX after the prototype 
			 //They're currently redundant, the control handles everything.
	key = {
		meta.cKey: exact;
	}
	actions = {
	    do_stage1;
	    insert1;
	    drop;
	    NoAction ;
	}
	default_action = insert1();
    }

    table track_stage2 {
	key = {
		meta.cKey: exact;
	}
	actions = {
	    do_stage2;
	    drop;
	    NoAction ;
	}
	default_action  = do_stage2();
    }

    action increment1 () {  //used if we found the same key in rKey1[index]
	rVals1.write((bit<32>)meta.index, meta.valInTable+1) ; //if it is, we just plug increment it once 
    }
    
    action swap1 () { //Used to force insertion into the first table and save the new minimums
	rKeys1.read(meta.cKey, (bit<32>)meta.index);
	rVals1.read(meta.cVal, (bit<32>)meta.index);
	rKeys1.write((bit<32>)meta.index, hdr.ipv4.dstAddr++hdr.ipv4.srcAddr++hdr.ipv4.protocol );
	rVals1.write((bit<32>)meta.index, 1 ) ;

    }
    action increment2 () { //rkeys2[index] == cKey
	rVals2.read(meta.valInTable, (bit<32>)meta.index) ; 
	rVals2.write((bit<32>)meta.index, meta.valInTable + meta.cVal ) ; 
    }
    action insert2() {	//nothing in rKeys2[index] yet
	rKeys2.write((bit<32>)meta.index, meta.cKey ) ;
	rVals2.write((bit<32>)meta.index, meta.cVal ) ;
    }
    action evict2() { //Evict the current couple because its count is lower, swap it in cKey,cVal
	rKeys2.write((bit<32>)meta.index, meta.cKey ) ;
	rVals2.write((bit<32>)meta.index, meta.cVal ) ; 
	meta.cKey = meta.keyInTable ;
	meta.cVal = meta.valInTable ;

    }

    apply {
        if (hdr.ipv4.isValid()) { //prepare forwarding off ipv4 fields
            ipv4_lpm.apply();
        }

	//stage1
	meta.cKey = hdr.ipv4.dstAddr++hdr.ipv4.srcAddr++hdr.ipv4.protocol ; //key of incoming packet
	hash( //hash said key, push it into meta.index
		meta.index, HashAlgorithm.crc16, //read index with the hash of stage 1 
		32w0,                         //currently crc16. TODO introduce (ax+b)%p hashes (a,b co-prime)?
		{
		  hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.ipv4.protocol 
		},
		32w100
	);
	rKeys1.read(meta.keyInTable, (bit<32>)meta.index); //keyInTable is the key actually in register 1 
	rVals1.read(meta.valInTable, (bit<32>)meta.index); //countInTable is the 	

	if (meta.valInTable == 0 ) { //We check if it's an empty slot first. If it is, we just slot in.
		insert1();
		exit ; 
	} 
	else if (meta.keyInTable == meta.cKey ) { //Next we check if it's the same key 
		increment1();
		exit ;
	} else { //Final case: always slot it in, save the old values in metadata fields cKey, cVal
		swap1() ;
	}
	

	//stage2. Mostly the same
	hash(meta.index, HashAlgorithm.csum16,
		32w0,
		{
		  hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.ipv4.protocol
		},
		32w100);
	rKeys2.read(meta.keyInTable, (bit<32>)meta.index) ; 
	if (meta.cKey == meta.keyInTable ) { //Keys Match ! 
		increment2();
	}
	else if (meta.valInTable == 0 ) { //Empty slot 
		insert2();
	} 
	else if (meta.valInTable < meta.cVal ) { //Evict lower count, swap it with rolling minimum
		evict2();
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
