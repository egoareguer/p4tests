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
typedef bit<32> number_t;

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

const bit<16> P4CALC_ETYPE = 0x1234;
const bit<8>  P4CALC_P     = 0x50;   // 'P'
const bit<8>  P4CALC_4     = 0x34;   // '4'
const bit<8>  P4CALC_VER   = 0x01;   // v0.1
const bit<8>  P4CALC_MULT  = 0x2a;   // '*'
const bit<8>  P4CALC_PLUS  = 0x2b;   // '+'
const bit<8>  P4CALC_MINUS = 0x2d;   // '-'
const bit<8>  P4CALC_DIV   = 0x2f;	 // '/'
const bit<8>  P4CALC_AND   = 0x26;   // '&'
const bit<8>  P4CALC_OR    = 0x7c;   // '|'
const bit<8>  P4CALC_CARET = 0x5e;   // '^'

header p4calc_t {
    bit<8>  P4CALC_P;
    bit<8>  P4CALC_4;
    bit<8>  P4CALC_VER;
    bit<8>  op;
    bit<32> OperandA;
    bit<32> OperandB;
    bit<32> res;
}

struct metadata {
	number_t to_log;
	number_t to_exp;
	number_t res;
	number_t log1;
	number_t log2;
	number_t exp;
	bool	 multFlag;
	bool	 divFlag;
	bool	 approxFlag;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
	p4calc_t	 p4calc;
}

// register<bit<256>>(8) math_reg; //8 buffers seem plenty

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
			P4CALC_ETYPE : check_p4calc;
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

	state check_p4calc {
		transition select (
			packet.lookahead<p4calc_t>().P4CALC_P,
			packet.lookahead<p4calc_t>().P4CALC_4,
			packet.lookahead<p4calc_t>().P4CALC_VER) {
				(P4CALC_P, P4CALC_4, P4CALC_VER) : parse_p4calc;
				default : accept;
		}
	}

	state parse_p4calc {
		packet.extract(hdr.p4calc);
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

	action send_back(bit<32> result) {
    bit<48> tmp;
    hdr.p4calc.res = result ;
    tmp = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = tmp ;
    standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    action operation_add() {
    send_back(hdr.p4calc.OperandA + hdr.p4calc.OperandB);
    }
    action operation_sub() {
    send_back(hdr.p4calc.OperandA - hdr.p4calc.OperandB);
    }
    action operation_and() {
    send_back(hdr.p4calc.OperandA & hdr.p4calc.OperandB);
    }
    action operation_or() {
    send_back(hdr.p4calc.OperandA | hdr.p4calc.OperandB);
    }
    action operation_xor() {
    send_back(hdr.p4calc.OperandA ^ hdr.p4calc.OperandB);
    }
	action write_log(bit<10> val) {
		meta.res=(bit<32>)val;
	}
	action write_exp(bit<32> val) {
		meta.res=val;
	}
	table log_val { //It seems like calling the same table twice in a row is not possible with v1model. The compiler fails the attempt with:
	key = { meta.to_log : lpm;
	}
	actions = { 
		NoAction;
		drop;
		write_log;
	}
	default_action = NoAction();
		const entries = {
			 #include "./tables/log_table_32bits_6precision.txt"
		}
	}

	table log_val2 { 
		key = { meta.to_log : lpm;
		}
		actions = { 
			NoAction;
			drop;
			write_log;
		}
		default_action = NoAction();
		const entries = {
			#include "./tables/log_table_32bits_6precision.txt"			
		}
	}
	table exp_val { 
		key = { meta.to_exp : exact;
		}
		actions = { 
			NoAction;
			drop;
			write_exp;
		}
		default_action = NoAction();
		const entries = {
			#include "./tables/exp_table_32bits_10precision.txt"			
		}
	}
	action operation_mult() {
		meta.multFlag   = true;
		meta.approxFlag = true;
	}
	action operation_div() {
		meta.divFlag    = true;
		meta.approxFlag = true;
	}
	table calculate {
        key = {
            hdr.p4calc.op        : exact;
        }
        actions = {
            operation_add;
            operation_sub;
            operation_and;
            operation_or;
            operation_xor;
            drop;
			operation_mult;
			operation_div;
        }
        const default_action = drop();
        const entries = {
            P4CALC_PLUS : operation_add();
            P4CALC_MINUS: operation_sub();
            P4CALC_AND  : operation_and();
            P4CALC_OR   : operation_or();
            P4CALC_CARET: operation_xor();
			P4CALC_MULT : operation_mult();
			P4CALC_DIV  : operation_div();
        }
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
		if (hdr.p4calc.isValid()) {
			calculate.apply();		// will apply the correct operation 
			bit<32> tmp;			// The reason why we have to use two log tables and put them here is 
										// >1) We can't invoke tables from actions
										// >2) On v1model, calling the same tables more than once appear to throw an error
										// Note that (2) is not necessarily a v1model limitation - it could extend to hardward implementations !
										// >3) Having two possible -even mutually distinct- calls of the same table also appears to be impossible! 

		// A*B ~ exp( log(a)+log(b) )
			if (meta.approxFlag) {
				meta.to_log=hdr.p4calc.OperandA;
				log_val.apply();
				tmp = meta.res;
				meta.to_log=hdr.p4calc.OperandB;
				log_val2.apply();
				if (meta.multFlag) {
					meta.to_exp=tmp + meta.res;
				} else if ( meta.divFlag ) {
					meta.to_exp=tmp - meta.res;
				}
				exp_val.apply();
				send_back(meta.res);
			}
		}
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
		packet.emit(hdr.p4calc);
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

