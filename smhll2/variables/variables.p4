// NUM_HLL_ENTRIES is how many short bytes we give an HLL data structure. It correlates positively to its precision
#define NUM_HLL_REGISTERS 16
// NUM_N_FLOWS is how many HLL data structures we allocate. It is dissociated from the estimation's precision
#define NUM_N_FLOWS 8
// INDEX_WIDTH is merely so we don't write in the wrong data structure block when we touch up NUM_HLL ENTRY. It's to avoid messing up the algorithm's precision with programmed errors
// INDEX_WIDTH = log2(NUM_HLL_REGISTERS) - 1 (Minus one to account for p4's big endian bit slicing)
#define INDEX_WIDTH 3
