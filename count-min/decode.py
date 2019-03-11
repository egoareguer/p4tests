#!/usr/bin/python

#Note: need to reverse endianness

def int_to_sbin(integ):
	#Takes i, return its a string of its value in binary
	if (integ<=1):
		return(str(integ&1))
	else:
		return(int_to_sbin(integ>>1)+str(integ&1))
def bin_to_int(string):
	res=0
	for i in range(len(string)):
		if (int(string[i])!=0):
			res=res+2**(len(string)-1-i)
	return(res)

def decode_ip_port(key):
	str_bkey=int_to_sbin(key) #[::-1]
	ip=str_bkey[-32:]
	ip1,ip2,ip3,ip4=ip[:-24],ip[-24:-16],ip[-16:-8],ip[-8:]
	port=str_bkey[:-32]
	return(bin_to_int(ip1),bin_to_int(ip2),bin_to_int(ip3),bin_to_int(ip4),bin_to_int(port))

def decode_ip(key):
	str_ip=int_to_sbin(key)
	ip1,ip2,ip3,ip4=str_ip[:-24],str_ip[-24:-16],str_ip[-16:-8],str_ip[-8:]
	return(bin_to_int(ip1),bin_to_int(ip2),bin_to_int(ip3),bin_to_int(ip4))

def chain(key_l):
	res=[]
	for i in range(len(key_l)):
		d=decode_ip_port(key_l[i])
		if (d!=(0,0,0,0,0)):
			res.append(d)
	res.sort()
	print(res)
	return(res)
		


#250, 200, 150 & 100 packets per ip per class

hh_reg= [ 153376244829721, 39355170337881, 237599376452653, 94533345310338, 70585804571631, 132988862133415, 68872280909666, 24583783280970, 228927897124966, 74366211109082, 182349460672912, 67407390460886, 80049931802260, 8089025731149, 111400324141715, 71998468158854, 96820310842821, 189280619911256, 118314352987642, 267945707868148, 93828052033705, 16033207182484, 192812659191777, 120131943135220, 152820593792970, 159081486840135, 224675795547451, 259081785214270, 17821115226028, 272608688146027, 208977633987571, 40886301159624, 123686166295953, 7405208579706, 272288931416123, 235341147330313, 226168294640472, 17436503717844, 35391303529871, 9066780136177, 241259725090854, 104864750040307, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

chain(hh_reg)
