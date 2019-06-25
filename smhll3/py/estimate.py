#!/usr/bin/python
import os
import scipy.integrate as integrate
import scipy.special as special
from ast import literal_eval
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
# print("alpha:", 1/(m*integrale[0]))
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
# print("res", res, "sum:",s, "m:",m, "alpha",alpha)
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

def file_est(n_ent):
        # int n_ent is how many entries there are (NUM_HLL_REGISTERS)
        
	# Assumes all four lists are present

        # First, read the file and decode it, saving the res in four lists

        pace=60
        
	str_n_ent=str(n_ent)
	filename="../records/regentries_"+str_n_ent+".txt"
	rfile=open(filename,'r')
	line=rfile.readline()[:-1] # Minus the final \n character
	count=0
        sIpL,dIpL,sPoL,pLenL=["sip"],["dip"],["spo"],["plen"]
	while (line):
		es,a=calc_estimate(64,literal_eval(line))
		det=count%4
                amount=((count-det)/4+1)*pace
                delta=abs(amount-es)
                
                rel_e=delta/amount
                if (det==0):
			sIpL.append(es)
                        sIpL.append(rel_e)
                        print(delta)
                        print(amount)
                elif (det==1):
			dIpL.append(es)
                        dIpL.append(rel_e)
		elif (det==2):
			sPoL.append(es)
                        sPoL.append(rel_e)
		else:
			pLenL.append(es)
		line=rfile.readline()[:-1]
		count+=1
	rfile.close()
        return(sIpL,dIpL,sPoL,pLenL)

def write_ests(l,n_ent):
        # l the list to write, with:
        # l[0] should be a comment
        # Then, odd indexes should be the estimate
        # while even indexes should be the error

        dfilename="../records/est_"+str(n_ent)+'_'+l[0]+'.txt'
	wfile=open(dfilename,'w')
        for i in range((len(l)-1)/2):
                wfile.write('Estimate: '+str(l[2*i+1])+', Relative error:')
                wfile.write(str(l[2*i+2])+'\n')
        wfile.close()

"""
rfilename="../records/regentries_64.txt"
rfile=open(rfilename,'r')
line=rfile.readline()[:-1] # Minus the \n
count=0
sIpL,dIpL,sPoL,pLenL=["SrcIP List"],["DstIP List",],["SrcPort List"],["PktLen List"]
while (line):
	res,a=calc_estimate(64,literal_eval(line))
	det=count%4
	if (det==0):
		sIpL.append(res)
	elif (det==1):
		dIpL.append(res)
	elif (det==2):
		sPoL.append(res)
	else:
		pLenL.append(res)
	line=rfile.readline()[:-1]
	count+=1
rfile.close()

print(sIpL)
print(dIpL)
print(sPoL)
print(pLenL)
"""
n_entries=64
l1,l2,l3,l4=file_est(n_entries)
write_ests(l1,n_entries)

#l=[8, 8, 8, 7, 12, 7, 9, 5, 7, 7, 8, 6, 8, 5, 5, 7, 8, 6, 10, 9, 8, 8, 6, 12, 6, 11, 5, 5, 6, 5, 5, 11]
#calc_estimate(32,l)
