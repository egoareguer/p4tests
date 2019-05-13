SYN flag cardinality can be obtained with a simple counter
Other features (IPsrc, IPdst, srcPort, PktLen) require using an HLL instance each
We give them N consecutive entries per dstPort in a [feat]_masterRegister instance
instance_type lets us know which packets aren't recirculated

In order to process the correct feature, we need to keep track of which ones we have(n't) already done for this packet
To do so, we can use ethertype to flag which feature we're processing on this run-through provided we pick unused ethertype values


START
Parse packets 
If instance_type==0 (Non recirculated packet) && SYN
	SYN_COUNTER++
exact match on hdr.tcp.dstPort,			
	write meta.portBlock
	//exact because we assume we know exactly which top K ports we're looking for
exact match on hdr.ethernet.ethertype
	write meta.feature
	// meta.feature in {IPsrc, IPdst, srcPort, PktLen}
exact match on meta.feature
	apply matching feature_hash 
	// we can't just pass an argument due to register references having to be compile constants

feature_hash()
	meta.hash			<- crc32_custom hash of (meta.feature)
	meta.index			<- hash[7:0]
	meta.remnant		<- hash[31:8]
	meta.address		<- index+N*meta.portBlock
	meta.current_zeroes <- feature_masterRegister(address) //This forces the last match

lpm match on meta.remnant
	write meta.these_zeroes
	//This is the most efficient way to count zeroes, only [remnant length] entries needed
exact match on meta.feature 
	apply feature_write_zeroes
	//Second call of the same table: need to duplicate it. Thankfully, it only has [num feature] entries, so it's lightweight

feature_write_zeroes
	push max(meta.current_zeroes, meta.these_zeroes) at feature_masterRegister(address)
	
exact match on hdr.ethernet.ethertype
	increment & recirculate
	OR
	drop packet
