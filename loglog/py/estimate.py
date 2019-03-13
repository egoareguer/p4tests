#!/usr/bin/python
import os
import scipy.integrate as integrate
import scipy.special as special
from numpy import log, inf, inf

#TODO read parameters from the command line

#Reminder: With m substreams,
# 	   E = alpha(m)*m*m*(sum (i->m) [ 2^( - max (zeroes) ) ] ) 
#    With: alpha(m) = m * (integrate (0 -> infinite) [ ( log2((2+u)/(1+u)) )^m ] du ) ^ -1  
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
	sum=0
	for i in range(m):
		sum=sum+2**(-(zeroes[i])) 
	res=alpha*m*m/sum
	print("sum:",sum, "m:",m)
	return(res,alpha)

register1=[ 10, 10, 10, 7, 9, 8, 7, 7, 8, 5, 9, 9, 8, 7, 10, 11, 10, 8, 6, 7, 8, 9, 8, 10, 6, 6, 8, 17, 6, 8, 7, 9, 9, 7, 7, 9, 6, 10, 6, 6, 7, 8, 13, 7, 8, 11, 10, 7, 8, 6, 6, 6, 10, 7, 12, 6, 6, 8, 9, 5, 7, 9, 8, 12, 7, 6, 9, 7, 7, 7, 11, 7, 9, 7, 9, 8, 8, 8, 10, 9, 6, 8, 12, 8, 7, 9, 6, 7, 10, 5, 7, 10, 8, 8, 6, 9, 6, 8, 7, 12, 7, 10, 7, 7, 8, 8, 7, 6, 6, 8, 8, 12, 9, 7, 7, 6, 7, 5, 10, 8, 10, 5, 6, 8, 8, 7, 9, 8, 7, 7, 10, 9, 6, 8, 7, 6, 7, 9, 8, 7, 12, 9, 6, 8, 10, 6, 6, 6, 9, 7, 9, 6, 6, 7, 7, 7, 9, 9, 9, 7, 6, 6, 6, 8, 8, 7, 11, 9, 5, 5, 14, 9, 7, 7, 8, 7, 12, 12, 6, 6, 10, 8, 7, 10, 7, 7, 8, 8, 7, 9, 9, 11, 7, 9, 10, 13, 10, 7, 11, 6, 9, 6, 8, 9, 9, 6, 6, 7, 6, 13, 8, 8, 9, 5, 13, 8, 6, 9, 8, 14, 10, 6, 9, 9, 7, 7, 7, 6, 7, 8, 9, 8, 7, 8, 10, 12, 8, 9, 9, 5, 6, 7, 7, 7, 7, 9, 7, 10, 8, 10, 9, 6, 7, 6, 6, 7]

print(calc_estimate(m,register1))

