import re

file = open("test.txt","r")

file_data = file.readlines()

x=1
port = 0
for line in file_data:

	portobj = re.match(r'([^\d]*)([\d]{1,5})(.*)tcp',line,re.M)

	ipobj = re.match(r'(([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3}))',line,re.M)

	if x==0 and ipobj:
		print ipobj.group(1)+":"+port+" [TCP]"

	else:
		x=1

	if portobj:
		port = portobj.group(2)
		x=0
	#print ip+":"+port
