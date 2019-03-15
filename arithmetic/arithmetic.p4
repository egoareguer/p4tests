/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//Constant definitions
const bit<16> TYPE_IPV4 = 0x800;



// * -* -*- -*- -*- -*- -*- *- HEADERS -* -*- -*- -*- -*- -*- *- * //

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> hash_t;
typedef bit<64> number_t;

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
	number_t to_log;
	number_t to_exp;
	number_t res;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

register<bit<256>>(8) math_reg; //8 buffers seem plenty

// * -* -*- -*- -*- -*- -*- *- PARSER -* -*- -*- -*- -*- -*- *- * // 

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

// * -* -*- -*- -*- -*- -*- *- CHECKSUM -* -*- -*- -*- -*- -*- *- * // 
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}
// * -* -*- -*- -*- -*- -*- *- INGRESS -* -*- -*- -*- -*- -*- *- * //

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
	action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

	action const_mult() { 
	/*	Multiplying by an int is the same as multiplying by its component powers of two with bit shifts & addition
		We can't really assume anything about what the p4 target will actually support
		"Division can be implemented by rewriting multiplication with the inverse-" (Evaluating Flexbile Packet Processing [...]) // But that implies floating point arithmetic
	*/	
	// 
	}

	action arbitrary_mult() { 
	/*	Here, can't use base 2 decomposition, so we have to approximate the operation.			
		The magic word is: 
		***** A*B = exp(log(A)+log(B)) *****
	*/
	}

	action push_log(number_t value) {
		meta.res = value;
	}

	table log_vals {
		/* For N bits number, using a window of calculation accuracy of size m with 1 <= m <= N, the entries contain
		   all 0^n ++ 1 ++ (0|1)^min(m-1,N-n-1) ++ x^(max(0,N-n-m)) where x = Don't care bit, where 1 <= n < N
		   Each entry to the l bit encoded log value of the average number matched by this entry	

		   Parameters: l, m, N 
		   With N = 64 bits, supposedly it's possible to hit 1% precision with 2048 TCAM entries
		*/
		key = {
			hdr.meta.to_log;
		}
		actions = { 
			NoAction;
			drop;
			push_log;
		}
		size = 2048;
		default_action = NoAction();
		const entries = {

		}
	}

	table exp_vals {

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
        }
    }
}

// * -* -*- -*- -*- -*- -*- *- EGRESS -* -*- -*- -*- -*- -*- *- * // 

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

// * -* -*- -*- -*- -*- -*- *- CHECKSUM -* -*- -*- -*- -*- -*- *- * // 

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

// * -* -*- -*- -*- -*- -*- *- DEPARSER -* -*- -*- -*- -*- -*- *- * //

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

// * -* -*- -*- -*- -*- -*- *- SWITCH -* -*- -*- -*- -*- -*- *- * //

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
