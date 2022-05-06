///// ***** GENERAL CONSTANTS ***** /////

const bit<16> TYPE_IPV4 = 0x800;
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

///// ***** HYPERLOGLOG RELATED CONSTANTS ***** /////

// NUM_HLL_ENTRIES is how many short bytes we give an HLL data structure. It correlates positively to its precision
#define NUM_HLL_REGISTERS 256
// NUM_N_FLOWS is how many HLL data structures we allocate. It is dissociated from the estimation's precision
#define NUM_N_FLOWS 2
// INDEX_WIDTH is merely so we don't write in the wrong data structure block when we touch up NUM_HLL ENTRY. It's to avoid messing up the algorithm's precision with programmed errors
// INDEX_WIDTH = log2(NUM_HLL_REGISTERS) - 1 (Minus one to account for p4's big endian bit slicing)
#define INDEX_WIDTH 7

// For Sha256, which is also how wide v1model allows bit slicing
#define HASH_WIDTH 256

///// ##### END HLL RELATED CONSTANTS ##### /////

///// ***** P4DUMP HEADER RELATED CONSTANTS *****/////

//P4dump header fields
const bit<16> 	P4DUMP_ETYPE 	= 0x04d5; // 1237
const bit<16>   P4UPDATE_ETYPE  = 0x04d4; // 1236

const bit<8>  	P4DUMP_P	   	= 0x50;
const bit<8>  	P4DUMP_4		= 0x34;
const bit<8>	P4DUMP_D		= 0x44;
const bit<8>	P4DUMP_VER		= 0x01;
//Operation codes
const bit<32> P4D_CODE_SRC_IP	= 0x90A;
const bit<32> P4D_CODE_DST_IP 	= 0x90B;
const bit<32> P4D_CODE_SRC_PO 	= 0x90C;
const bit<32> P4D_CODE_PKT_LE 	= 0x90D;
const bit<32> P4D_CODE_PKT_CO 	= 0x90E;
const bit<32> P4D_CODE_ALL		= 0x90F;

///// ##### END P4DUMP HEADER CONSTANTS ##### /////

///// ***** SMHLL TYPEDEFS *****/////

typedef bit<16> portBlock_t;
typedef bit<32> address_t;
typedef bit<32> hash_t;
typedef bit<56> remnant_t;
typedef bit<16>  index_t;
typedef bit<6>  short_byte_t;
typedef bit<8>  dumpFlag_t;
typedef bit<16> recirc_key_t;
