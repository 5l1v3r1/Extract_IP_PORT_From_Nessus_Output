#/usr/bin/python

import re
import os
import csv

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


def banner():

        print O+'#############################################################################################'
        print '#                          <<<Nessus Vulnerability Extractor>>>                             #'
        print '#                                                                                           #'
        print '#                                Made by <<RISHABH SHARMA>>                                 #'
        print '#                                  Twitter : @blacknet22                                    #'
        print '#                             operating system : Linux/Windows                              #'
        print '#                                                                                           #'
        print '#############################################################################################'+END


def Name_Sanitizer(vuln_name):

	sanitize = ["/","*","\\","?","_","\",","(",")","-","?","'","\\","[","]","{","}"]
	for x in sanitize:
		vuln_name = vuln_name.replace(x," ")
	return vuln_name

def Multiple_IP_Port_Checker(vuln_path, ip_port):
        with open (vuln_path) as check_file:
                value = ip_port in check_file.read()
                check_file.close()
                return value


def Nessus_Extractor(Folder_Path):
	print BOLD+P+"Start Analysing Nessus CSV Output....\n"+END
        file = open(Folder_Path, 'r')
        reader = csv.reader(file)
        for line in reader:
                if (line[3] == "Critical"): 
                        vuln_type = str(line[3])
                        vuln_name = str(line[7])
                        vuln_name = Name_Sanitizer(vuln_name)
			#print P+vuln_type +' : '+ vuln_name
                        vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
			if os.path.isfile(vuln_path):
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
					pass
				else:
					print P+vuln_type+' : '+ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
                        else:
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
					pass
				else:
					print P+vuln_type+' : '+ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
		if (line[3] == "High"): 
                        vuln_type = str(line[3])
                        vuln_name = str(line[7])
                        vuln_name = Name_Sanitizer(vuln_name)
                        #print R+vuln_type +' : '+ vuln_name
                        vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
                        if os.path.isfile(vuln_path):
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print R+vuln_type+' : '+ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
                        else:
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print R+vuln_type+' : '+ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                               		file_save.close()
		if (line[3] == "Medium"):
                        vuln_type = str(line[3])
                        vuln_name = str(line[7])
                        vuln_name = Name_Sanitizer(vuln_name)
                        #print Y+vuln_type +' : '+ vuln_name
                        vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
                        if os.path.isfile(vuln_path):
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print Y+vuln_type+' : '+ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
                        else:
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print Y+vuln_type+' : '+ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
		if (line[3] == "Low"):
                        vuln_type = str(line[3])
                        vuln_name = str(line[7])
                        vuln_name = Name_Sanitizer(vuln_name)
                        #print G+vuln_type +' : '+ vuln_name
                        vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
                        if os.path.isfile(vuln_path):
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print G+vuln_type +' : '+ ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
                        else:
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print G+vuln_type +' : '+ ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
		if (line[3] == "None"):
                        vuln_type = str(line[3])
                        vuln_name = str(line[7])
                        vuln_name = Name_Sanitizer(vuln_name)
                        #print B+vuln_type +' : '+ vuln_name
                        vuln_path = 'Output/'+vuln_type+'/'+vuln_name+'.txt'
                        if os.path.isfile(vuln_path):
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					#print B+vuln_type +' : '+ ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()
                        else:
                                file_save = open(vuln_path,'a+')
                                ip_port = line[4] +":"+line[6]+" ["+line[5]+"]"
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					#print B+vuln_type +' : '+ ip_port+END
                                	file_save.write(ip_port)
                                	file_save.write('\n')
                                	file_save.close()

def main():
        banner()
        Output_Path =  "Output"
        Output_Critical = "Output/Critical"
        Output_High = "Output/High"
        Output_Medium = "Output/Medium"
        Output_Low = "Output/Low"
	Output_Info = "Output/None"
        if not os.path.exists(Output_Path):
                os.makedirs(Output_Path)
        if not os.path.exists(Output_Critical):
                os.makedirs(Output_Critical)
        if not os.path.exists(Output_High):
                os.makedirs(Output_High)
        if not os.path.exists(Output_Medium):
                os.makedirs(Output_Medium)
        if not os.path.exists(Output_Low):
                os.makedirs(Output_Low)
	if not os.path.exists(Output_Info):
                os.makedirs(Output_Info)
        try:
		import csv
                Folder_Path = raw_input(BOLD+Y+"Enter Nessus CSV Output File Name: ")
                Nessus_Extractor(Folder_Path)
		print O+'________________________________________________________________________'+END
		print BOLD+O+"Number Of Vulnerabilities Found:"+END
		print O+'------------------------------------------------------------------------'+END
		print '\n'
		critical = len(os.listdir(Output_Critical))
		high = len(os.listdir(Output_High))
		medium = len(os.listdir(Output_Medium))
		low = len(os.listdir(Output_Low))
		info = len(os.listdir(Output_Info))
		print BOLD+P+"Total Critical Vulnerabilities Found: "+END,critical
        	print BOLD+R+"Total High Vulnerabilities Found: "+END,high
        	print BOLD+Y+"Total Medium Vulnerabilities Found: "+END,medium
        	print BOLD+G+"Total Low Vulnerabilities Found: "+END,low
        	print BOLD+B+"Total Info Vulnerabilities Found: "+END,info

        except KeyboardInterrupt:
                print "\nKeyboard Interrupt..."
        except IOError,i:
                print "\nInput Output Error..."
                print i
        except Exception,e:
                print "\nError in file..."
                print e
	except ImportError, e:
		print BOLD+R+"Python CSV module not installed..."+END

if __name__ =='__main__':
        main()
