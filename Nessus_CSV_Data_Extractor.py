#/usr/bin/python

import re
import os


# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
Y = '\033[93m'
BOLD = '\033[1m'
END = '\033[0m'

#banner

def banner():

        print O+'#############################################################################################'
        print '#                          <<<Nessus Vulnerability Extractor>>>                             #'
        print '#                                                                                           #'
        print '#                                Made by <<RISHABH SHARMA>>                                 #'
	print '#                                  Twitter : @blacknet22                                    #'
        print '#                                 operating system : KALI                                   #'
        print '#                                                                                           #'
        print '#############################################################################################'+END


def Nessus_Extractor(Folder_Path):
	print BOLD+P+"Start Analysing Nessus CSV Output....\n"+END
	counthigh = 0
	countmedium = 0
	countlow = 0
	with open(Folder_Path, 'r') as f:
		contents = f.readlines()
		for x in contents:
			searchobj = re.search(r'(")([\w]*)(",")(([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3}))(",")([\w]*)(",")(\d*)(",")([\w\s]*)(")',x,re.I)
			if searchobj:

				if (searchobj.group(2) == "High"):
					counthigh = counthigh + 1
					vuln_type = searchobj.group(2)
					vuln_name =  searchobj.group(14)
					vuln_name = vuln_name.replace('/','_')
					vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
					if os.path.isfile(vuln_path):
						file_save = open(vuln_path,'a+')
						ip_port = searchobj.group(4)+":"+searchobj.group(12)+" ["+searchobj.group(10)+"]"
						file_save.write(ip_port)
						file_save.write('\n')
						file_save.close()
					else:
						file_save = open(vuln_path,'a+')
                                                ip_port = searchobj.group(4)+":"+searchobj.group(12)+" ["+searchobj.group(10)+"]"
                                                file_save.write(ip_port)
                                                file_save.write('\n')
                                                file_save.close()

				if (searchobj.group(2) == "Medium"):
					countmedium = countmedium + 1
                                        vuln_type = searchobj.group(2)
                                        vuln_name =  searchobj.group(14)
					vuln_name = vuln_name.replace('/','_')
                                        vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
                                        if os.path.isfile(vuln_path):
                                                file_save = open(vuln_path,'a+')
                                                ip_port = searchobj.group(4)+":"+searchobj.group(12)+" ["+searchobj.group(10)+"]"
                                                file_save.write(ip_port)
                                                file_save.write('\n')
                                                file_save.close()
                                        else:
                                                file_save = open(vuln_path,'a+')
                                                ip_port = searchobj.group(4)+":"+searchobj.group(12)+" ["+searchobj.group(10)+"]"
                                                file_save.write(ip_port)
                                                file_save.write('\n')
                                                file_save.close()

				if (searchobj.group(2) == "Low"):
					countlow = countlow + 1
                                        vuln_type = searchobj.group(2)
                                        vuln_name =  searchobj.group(14)
					vuln_name = vuln_name.replace('/','_')
                                        vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
                                        if os.path.isfile(vuln_path):
                                                file_save = open(vuln_path,'a+')
                                                ip_port = searchobj.group(4)+":"+searchobj.group(12)+" ["+searchobj.group(10)+"]"
                                                file_save.write(ip_port)
                                                file_save.write('\n')
                                                file_save.close()
                                        else:
                                                file_save = open(vuln_path,'a+')
                                                ip_port = searchobj.group(4)+":"+searchobj.group(12)+" ["+searchobj.group(10)+"]"
                                                file_save.write(ip_port)
                                                file_save.write('\n')
                                                file_save.close()

	print BOLD+R+"Total High Vulnerabilities Found: "+END,counthigh
	print BOLD+Y+"Total Medium Vulnerabilities Found: "+END,countmedium
	print BOLD+G+"Total Low Vulnerabilities Found: "+END,countlow



def main():
        banner()
	Output_Path =  "Output"
	Output_High = "Output/High"
	Output_Medium = "Output/Medium"
	Output_Low = "Output/Low"
	if not os.path.exists(Output_Path):
		os.makedirs(Output_Path)
	if not os.path.exists(Output_High):
                os.makedirs(Output_High)
	if not os.path.exists(Output_Medium):
                os.makedirs(Output_Medium)
	if not os.path.exists(Output_Low):
                os.makedirs(Output_Low)
	try:
		Folder_Path = raw_input(BOLD+Y+"Enter Nessus CSV Output File Name: ")
		Nessus_Extractor(Folder_Path)
	except KeyboardInterrupt:
		print "\nKeyboard Interrupt..."
	except IOError,i:
		print "\nInput Output Error..."
		print i
	except Exception,e:
		print "\nError in file..."
		print e

if __name__ =='__main__':
        main()

