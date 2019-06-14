//P4dump header definition
header p4dump_t {
	bit<8>	P4DUMP_P;
	bit<8>	P4DUMP_4;
	bit<8>	P4DUMP_D;
	bit<8>	P4DUMP_VER;
	bit<32>	code;
	bit<32> port;
}
// dumpBlock header definition.
// We use 256 bits blocks as that's the max bit shift size in v1model
header dumpBlock_t {
	bit<256> value0;
	bit<256> value1;
	bit<256> value2;
	bit<256> value3;
	bit<256> value4;
	bit<256> value5;
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
