#!/usr/bin/python
import os
import scipy.integrate as integrate
import scipy.special as special
from ast import literal_eval
from numpy import log, inf, inf
import matplotlib.pyplot as plt

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

        pace=75
        
	str_n_ent=str(n_ent)
	filename="../records/regentries_75.txt"
	rfile=open(filename,'r')
	line=rfile.readline()[:-1] # Minus the final \n character
	count=0
        sIpL,dIpL,sPoL,pLenL=["sip"],["dip"],["spo"],["plen"]
        legend="Estimate","True value","Relative Error"
	while (line):
		es,a=calc_estimate(64,literal_eval(line))
		det=count%4
                amount=((count-det)/4+1)*pace
                delta=abs(amount-es)
                
                rel_e=delta/amount
                values=es, amount, rel_e
                print (es)
                if (det==0):
			sIpL.append(values)
                elif (det==1):
		        dIpL.append(values)
		elif (det==2):
                        sPoL.append(values)
		else:
			pLenL.append(values)
		line=rfile.readline()[:-1]
		count+=1
	rfile.close()
        return(sIpL,dIpL,sPoL,pLenL)

def write_ests(l,n_ent):
        # l the list to write, with:
        # l[0] should be the key
        # Then, odd indexes should be the estimate
        # while even indexes should be the error

        dfilename="../records/est_"+str(n_ent)+'_'+l[0]+'_step=75.txt'
	wfile=open(dfilename,'w')
        for i in range((len(l)-1)):
                wfile.write('Estimate: % 10.3f' %l[i+1][0])
                wfile.write('.   Actual count: % 7d' %l[i+1][1])
                wfile.write('.   Relative error: % .2f' %(l[i+1][2]*100)+'% \n')
        wfile.close()


def plot (l1,l2,l3):
        # li[1:] is the list of register entries
        # li[0] is its key for the legend
        # n_ent is how many entries there are.
        # They're all the same size

        # Goal i : four reference, estimates
        refl=[i[1] for i in l1[1:]]
        under_ref=[i*0.9 for i in refl]
        over_ref =[i*1.1 for i in refl]
        n=len(l1)-1
        es1=[i[0] for i in l1[1:]]
        es2=[i[0] for i in l2[1:]]
        es3=[i[0] for i in l3[1:]]
        step=refl[0]
        plt.plot(refl, refl, 'r--', refl, under_ref, 'b--', refl, over_ref, 'g--')
        plt.plot(refl, es1, 'bs', refl, es2, 'gs', refl, es3, 'rs')
        plt.show()

        
n_entries=64
l1,l2,l3,l4=file_est(n_entries)
write_ests(l1,n_entries)
write_ests(l2,n_entries)
write_ests(l3,n_entries)
write_ests(l4,n_entries)

plot(l1,l2,l3)

#l=[8, 8, 8, 7, 12, 7, 9, 5, 7, 7, 8, 6, 8, 5, 5, 7, 8, 6, 10, 9, 8, 8, 6, 12, 6, 11, 5, 5, 6, 5, 5, 11]
#calc_estimate(32,l)
