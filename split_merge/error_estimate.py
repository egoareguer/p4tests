#!/usr/bin/env python

import scipy as sp

# Estimating the error when account for bitmap estimate "Flows ~ N*ln(N/Z), with N the bitmap's size, Z how many zeroes

bitwidth=32 # We'll do a range on it

def error(N,bitwidth):
	bn=bin(N)[2:]
	bn=bn.zfill(bitwidth)
	Z=0
	for i in bn:
		if int(i)==0:
			Z=Z+1
	if Z!=0:
		est=bitwidth*sp.log(float(bitwidth)/Z)
		print ("bitwidth ="+str(bitwidth),"estimate ="+str(est),"difference ="+str(est-(bitwidth-Z)), "binary ="+bn)
			
a=0
for i in range(bitwidth):
	a=a+2**i
	error(a,bitwidth)
