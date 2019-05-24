Note: register.read will crash when attempting an out-of-range read. 

In the .p4 file:
	>How many entries for a HLL structure
		NUM_HLL_REGISTERS 	
	>How many flows have a HLL structure
		NUM_N_FLOWS
	>Related: meta.index's width 
		=log2(NUM_HLL_REGISTERS)

In the .py scripts:

spam: port range
	>How many flows
		N_FLOWS

Tied to this, we can use "smaller tables" for the countings, so that it's lighter on memory
