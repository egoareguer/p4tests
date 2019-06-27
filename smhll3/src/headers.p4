//P4dump header definition
header p4dump_t {
	bit<8>	P4DUMP_P;
	bit<8>	P4DUMP_4;
	bit<8>	P4DUMP_D;
	bit<8>	P4DUMP_VER;
	bit<32>	code;
	bit<32> port;
	bit<32> sequence_code;
	bit<32> separator;
}
// dumpBlock header definition.
// We use 256 bits blocks as that's the max bit shift size in v1model

//Cutoff points: 
// 32 entries <-> 1 block
// So: 32:1		64:2	128:4	256:8 	512:16	  1024:32 
// 1024 is the limit to fit in 

header dumpBlock_t {
	bit<192> value0;
	bit<192> value1;
	bit<192> value2;
	bit<192> value3;
	bit<192> value4;
	bit<192> value5;
	bit<192> value6;
	bit<192> value7;
/*	bit<192> value8;
	bit<192> value9;
	bit<192> value10;
	bit<192> value11;
	bit<192> value12;
	bit<192> value13;
	bit<192> value14;
	bit<192> value15;
	bit<192> value16;
	bit<192> value17;
	bit<192> value18;
	bit<192> value19;
	bit<192> value20;
	bit<192> value21;
	bit<192> value22;
	bit<192> value23;
	bit<192> value24;
	bit<192> value25;
	bit<192> value26;
	bit<192> value27;
	bit<192> value28;
	bit<192> value29;
	bit<192> value30;
	bit<192> value31;
	*/
}

// Standard fare ethernet, ipv4, tcp header definition
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
