#!/usr/bin/python
import os
import scipy.integrate as integrate
import scipy.special as special
from numpy import log, inf, inf

#Reminder: With m substreams,
# 	   E = alpha(m)*m*m*(sum (i->m) [ 2^( - max (zeroes) ) ] ) 
#    With: alpha(m) = m / (integrate (0 -> infinite) [ ( log2((2+u)/(1+u)) )^m ] du )   
#    Suggested alpha values:
#	alpha (16) = 0.673
#	alpha (32) = 0.697 
#	alpha (64) = 0.709 
#	alpha (m)  = 0.7213/(1+1.079/m) for m >= 128

p=8
m=2**p

def calc_alpha(m): #Single call, can be substituted on compilation to insert alpha's value in the p4 program
	if   m == 16:
		return 0.673
	elif m == 32:
		return 0.697
	elif m == 64:
		return 0.709
	else:
		def integrand(u,m):
			return  ( log ((2+u)/(1+u))/ log(2) )**m 
		integrale = integrate.quad(integrand, 0, +inf, args=(m))
		print("alpha:", 1/(m*integrale[0]))
		return(1/(m*integrale[0]))

def calc_estimate(m,zeroes):
	alpha=calc_alpha(m)
#	if last_m!=m:
#		alpha = calc_alpha(m)
#		last_m=m
	s=0
	for i in range(m):
		s=s+2**(-(zeroes[i])) 
	res=alpha*m*m/s
	print("res", res, "sum:",s, "m:",m, "alpha",alpha)
	return(res,alpha)

def calc_blocks(f,m,tab):
	res_list=[]
	#f how many flows are in tab
	#m how many entries each HLL struct has
	alpha=calc_alpha(m)
	for i in range(f):
		s=0
		for j in range(m):
			s=s+2**(-tab[i*m+j])
		res=alpha*m*m*s
		res_list.append(res)
	print(res_list)

#calc_blocks(31,32,srcIP_masterReg)
l=[8, 8, 8, 7, 12, 7, 9, 5, 7, 7, 8, 6, 8, 5, 5, 7, 8, 6, 10, 9, 8, 8, 6, 12, 6, 11, 5, 5, 6, 5, 5, 11]
calc_estimate(32,l)
