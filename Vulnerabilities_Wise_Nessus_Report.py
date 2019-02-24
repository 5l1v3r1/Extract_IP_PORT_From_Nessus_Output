#/usr/bin/python

#import re
import os
import csv
import shutil
import xlwt
from xlwt import Workbook

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
        print '#                                Version : 1.1 (2019)                                       #'
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
				description = line[9]
				description = description.replace('\n',' ')
				solution = line[10]
				solution = solution.replace('\n',' ')
				ref = line[11]
				ref = ref.replace('\n',' ')
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
					pass
				else:
					print P+vuln_type+' : '+ip_port+END
					file_save.write("Description: "+description)
					file_save.write('\n')
					file_save.write("Solution: "+solution)
					file_save.write('\n')
					file_save.write("Ref: "+ref)
					file_save.write('\n')
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
				description = line[9]
				description = description.replace('\n',' ')
				solution = line[10]
				solution = solution.replace('\n',' ')
				ref = line[11]
				ref = ref.replace('\n',' ')
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print R+vuln_type+' : '+ip_port+END
					file_save.write("Description: "+description)
					file_save.write('\n')
					file_save.write("Solution: "+solution)
					file_save.write('\n')
					file_save.write("Ref: "+ref)
					file_save.write('\n')
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
				description = line[9]
				description = description.replace('\n',' ')
				solution = line[10]
				solution = solution.replace('\n',' ')
				ref = line[11]
				ref = ref.replace('\n',' ')
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print Y+vuln_type+' : '+ip_port+END
					file_save.write("Description: "+description)
					file_save.write('\n')
					file_save.write("Solution: "+solution)
					file_save.write('\n')
					file_save.write("Ref: "+ref)
					file_save.write('\n')
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
				description = line[9]
				description = description.replace('\n',' ')
				solution = line[10]
				solution = solution.replace('\n',' ')
				ref = line[11]
				ref = ref.replace('\n',' ')
				if (Multiple_IP_Port_Checker(vuln_path,ip_port)):
                                        pass
				else:
					print G+vuln_type +' : '+ ip_port+END
					file_save.write("Description: "+description)
					file_save.write('\n')
					file_save.write("Solution: "+solution)
					file_save.write('\n')
					file_save.write("Ref: "+ref)
					file_save.write('\n')
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
				description = line[9]
				description = description.replace('\n',' ')
				solution = line[10]
				solution = solution.replace('\n',' ')
				ref = line[11]
				ref = ref.replace('\n',' ')
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

		#Critical_Sheet
		wb = Workbook()
		sheet1 = wb.add_sheet('Critical')
		style = xlwt.easyxf('font: bold 1;')
		dir_count = len(os.listdir('Output/Critical'))
		c = 0 #column
		while (c < dir_count):
        		dir_names = os.listdir('Output/Critical')
        		for dir_name in dir_names:
				header = dir_name.replace('.txt','')
                		sheet1.write(0,c,header,style)
                		file = open('Output/Critical/'+dir_name,'r')
                		reading = file.readlines()
                		ipcount = len(reading)
                		#print ipcount
                		r = 1 #row
                		while (r < ipcount):
                        		for ip in reading:
                                		#print str(r)+":"+ip
                                		sheet1.write(r,c,ip)
                                		r = r+1
                        		file.close()
                		c = c + 1
		#High_Sheet
		sheet2 = wb.add_sheet('High')
		style = xlwt.easyxf('font: bold 1;')
		dir_count = len(os.listdir('Output/High'))
		c = 0 #column
		while (c < dir_count):
        		dir_names = os.listdir('Output/High')
        		for dir_name in dir_names:
				header = dir_name.replace('.txt',' ')
                		sheet2.write(0,c,header,style)
                		file = open('Output/High/'+dir_name,'r')
                		reading = file.readlines()
                		ipcount = len(reading)
                		#print ipcount
                		r = 1 #row
                		while (r < ipcount):
                        		for ip in reading:
                                		#print str(r)+":"+ip
                                		sheet2.write(r,c,ip)
                                		r = r+1
                        		file.close()
                		c = c + 1

		#Medium_Sheet
		sheet3 = wb.add_sheet('Medium')
		style = xlwt.easyxf('font: bold 1;')
		dir_count = len(os.listdir('Output/Medium'))
		c = 0 #column
		while (c < dir_count):
        		dir_names = os.listdir('Output/Medium')
        		for dir_name in dir_names:
				header = dir_name.replace('.txt',' ')
                		sheet3.write(0,c,header,style)
                		file = open('Output/Medium/'+dir_name,'r')
                		reading = file.readlines()
                		ipcount = len(reading)
                		#print ipcount
                		r = 1 #row
                		while (r < ipcount):
                        		for ip in reading:
                                		#print str(r)+":"+ip
                                		sheet3.write(r,c,ip)
                                		r = r+1
                        		file.close()
                		c = c + 1

		#Low_Sheet
		sheet4 = wb.add_sheet('Low')
		style = xlwt.easyxf('font: bold 1;')
		dir_count = len(os.listdir('Output/Low'))
		c = 0 #column
		while (c < dir_count):
        		dir_names = os.listdir('Output/Low')
        		for dir_name in dir_names:
				header = dir_name.replace('.txt',' ')
                		sheet4.write(0,c,header,style)
                		file = open('Output/Low/'+dir_name,'r')
                		reading = file.readlines()
                		ipcount = len(reading)
                		#print ipcount
                		r = 1 #row
                		while (r < ipcount):
                        		for ip in reading:
                                		#print str(r)+":"+ip
                                		sheet4.write(r,c,ip)
                                		r = r+1
                        		file.close()
                		c = c + 1

		#None_Sheet
		sheet5 = wb.add_sheet('None')
		style = xlwt.easyxf('font: bold 1;')
		dir_count = len(os.listdir('Output/None'))
		c = 0 #column
		while (c < dir_count):
        		dir_names = os.listdir('Output/None')
        		for dir_name in dir_names:
				header = dir_name.replace('.txt',' ')
                		sheet5.write(0,c,header,style)
                		file = open('Output/None/'+dir_name,'r')
                		reading = file.readlines()
                		ipcount = len(reading)
                		#print ipcount
                		r = 1 #row
                		while (r < ipcount):
                        		for ip in reading:
                                		#print str(r)+":"+ip
                                		sheet5.write(r,c,ip)
                                		r = r+1
                        		file.close()
                		c = c + 1

		wb.save('Vulnerabilities_Wise_Report.xls')


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
		shutil.rmtree('Output')

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
