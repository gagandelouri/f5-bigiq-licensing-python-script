# This script written to manage BIG-IP license activation with BIG-IQ License Manager
# Currently only support RegKey Pool
# Note: This is not F5 supported utilities. Use at your own risk.
#
# Revoke: python bigiplicmgr.py --licmgr_ip 192.168.110.52 --licmgr_adm admin --licmgr_pwd passw0rd --regkey_pool_name RegKeyPool --bigip_ip 192.168.101.121 --bigip_adm admin --bigip_pwd admin --action revoke-license
# Assign: python bigiplicmgr.py --licmgr_ip 192.168.110.52 --licmgr_adm admin --licmgr_pwd passw0rd --regkey_pool_name RegKeyPool --bigip_ip 192.168.101.121 --bigip_adm admin --bigip_pwd admin --action assign-license
# Author: Foo-Bang Chan, Modified by Gagan Delouri
# Date: 10 Sept 2017
# Version: 0.3
#
#
import argparse
import requests
import json
import base64
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='F5 BIG-IP License Manager Utilities')
parser.add_argument('--licmgr_ip', help='F5 license manager IP Address', required=True)
parser.add_argument('--licmgr_adm', help='F5 license manager admin username', required=True)
parser.add_argument('--licmgr_pwd', help='F5 license manager admin password', required=True)
parser.add_argument('--bigip_ip', help='BIG-IP IP address (license target)', required=False)
parser.add_argument('--bigip_adm', help='BIG-IP admin username (e.g. admin)', required=False)
parser.add_argument('--bigip_pwd', help='BIG-IP admin password', required=False)
parser.add_argument('--action', help='F5 license manager actions (dump-license, assign-license, revoke-license', required=True)
parser.add_argument('--regkey_pool_name', help='License Manager RegKey License Pool Name', required=False)
parser.add_argument('--regkey_string', help='Registration Key string. By default retrieve 1st available license string from LM. This to provide explicit RegKey', required=False)


headers = {
     'Content-Type': 'application/json'
}

####################################
# Function: Generate X-F5-Auth-Token
####################################
def ligmgr_authtoken (ip,username,password):
	url = 'https://'+ip+'/mgmt/shared/authn/login'
	payload = {
		'username': username,
		'password': password
	}
	resp = requests.post(url,headers=headers, data=json.dumps(payload), verify=False)
	json_data =  json.loads(resp.text)
	#print(json.dumps(resp.json(), indent=2))
	#print json_data['token']['token']
	return json_data['token']['token'];
print 'auth token-----------------------------------'
###############################################
# Function: Dump license Registration Pool Key
###############################################
def lm_dump_regpool(auth_token,ip,rpoolname):
	# Step 1: Lookup Registration Key Pool id
	url = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses?%24filter=name%20eq%20%27'+rpoolname+'%27'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url, headers=headers, verify=False)
	json_data =  json.loads(resp.text)
	#print(json.dumps(resp.json(), indent=2))
	id = json_data['items'][0]['id']

	# Step 2: Loop through all available Reg Key based on given RegKey Pool Name
	url2 = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+id+'/offerings/'
	resp2 = requests.get(url2, headers=headers, verify=False)
	json_data2 =  json.loads(resp2.text)
	print '-----------------------------------'
	print 'License key dump for '+rpoolname
	print '-----------------------------------'
	print '{:35s} {:20s} {:20s} {:20s}'.format('RegKey','DeviceName','DeviceAddress','Status') 

	for regkey in json_data2['items']:
		key = regkey['regKey']
		# Loop through and dump each RegKey members information.
		url3 = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+id+'/offerings/'+key+'/members/'
		resp3 = requests.get(url3, headers=headers, verify=False)
		json_data3 = json.loads(resp3.text)

		if len(json_data3['items']) > 0:
			print '{:35s} {:20s} {:20s} {:20s}'.format(key,json_data3['items'][0]['deviceName'],json_data3['items'][0]['deviceAddress'],json_data3['items'][0]['status'])
			#print key, "\t", json_data3['items'][0]['deviceName'], "\t\t", json_data3['items'][0]['deviceAddress'], "\t", json_data3['items'][0]['status']
		else:
			print key
	return;

###############################################
# Function: Get any unused Registration Key
###############################################
def lm_unused_regpool(auth_token,ip,rpoolname):
	url = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses?%24filter=name%20eq%20%27'+rpoolname+'%27'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url, headers=headers, verify=False)
	json_data =  json.loads(resp.text)
	#print(json.dumps(resp.json(), indent=2))
	#print json_data['items'][0]['id']
	id = json_data['items'][0]['id']

	url2 = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+id+'/offerings/'
	resp2 = requests.get(url2, headers=headers, verify=False)
	json_data2 =  json.loads(resp2.text)
	#print len(json_data2['items'])
	unused_string = ""
	for regkey in json_data2['items']:
		key = regkey['regKey']
		url3 = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+id+'/offerings/'+key+'/members/'
		resp3 = requests.get(url3, headers=headers, verify=False)
		json_data3 = json.loads(resp3.text)
		if len(json_data3['items']) == 0:
			unused_string = key
			break #Get the 1st unused key
	return unused_string;

def return_regpool_id(auth_token,ip,rpoolname):
	url = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses?%24filter=name%20eq%20%27'+rpoolname+'%27'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url, headers=headers, verify=False)
	json_data =  json.loads(resp.text)
	id = json_data['items'][0]['id']
	return id;

def return_device_uuid(auth_token,ip,regpool_id,regkey):
	url = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+regpool_id+'/offerings/'+regkey+'/members/'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	#print "URL: " + url
	resp = requests.get(url, headers=headers, verify=False)
	if resp.status_code != 200:
		#print "Device uuid Error: " + resp.content
		uuid = "null"
	else:
		json_data =  json.loads(resp.text)
		uuid = json_data['items'][0]['id']
	
	return uuid;

	#print(json.dumps(resp.json(), indent=2))
	


def return_device_regkey(auth_token,ip,rpoolname,deviceIP):
	url = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses?%24filter=name%20eq%20%27'+rpoolname+'%27'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url, headers=headers, verify=False)
	json_data =  json.loads(resp.text)
	id = json_data['items'][0]['id']

	url2 = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+id+'/offerings/'
	resp2 = requests.get(url2, headers=headers, verify=False)
	json_data2 =  json.loads(resp2.text)
	foundKey = ""
	for regkey in json_data2['items']:
		#print (regkey['regKey'])
		key = regkey['regKey']
		url3 = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+id+'/offerings/'+key+'/members/' 
		resp3 = requests.get(url3, headers=headers, verify=False)
		json_data3 = json.loads(resp3.text)
		if len(json_data3['items']) > 0:
			if json_data3['items'][0]['deviceAddress'] == deviceIP:
				#print "Match: " + deviceIP
				#print "RegKey is: " + key
				foundKey = key
				break
		else:
			foundKey = "null"
	
	return foundKey;



def lm_assign_regkey(auth_token,ip,bigip_ip,username,password,regkeypool_id,unused_regkey):
	url = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+regkeypool_id+'/offerings/'+unused_regkey+'/members/'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	payload = {
		'deviceAddress': bigip_ip,
		'username': username,
		'password': password
	}
	resp = requests.post(url,headers=headers, data=json.dumps(payload), verify=False)
	json_data = json.loads(resp.text)
	if resp.status_code != 200:
		print "-------------------"
		print "Assign RegKey Error"
		print "-------------------"
		print json.dumps(resp.json(), indent=2)
		print "-------------------------------------------------------------"
		print "URL: " + url
		print "-------------------------------------------------------------"
	else:
		print "-------------------------------------------------------------"
		print "License key " + unused_regkey + " successfully assigned"
		print "-------------------------------------------------------------"
		print(json.dumps(resp.json(), indent=2))
	return;


def lm_revoke_regkey(auth_token,ip,bigip_ip,username,password,regkeypool_id,uuid,regkey):
	url = 'https://'+ip+'/mgmt/cm/device/licensing/pool/regkey/licenses/'+regkeypool_id+'/offerings/'+regkey+'/members/'+uuid
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	payload = {
		'id': uuid,
		'username': username,
		'password': password
	}
	resp = requests.delete(url,headers=headers, data=json.dumps(payload), verify=False)
	if resp.status_code != 200:
		print "-------------------"
		print "Revoke RegKey Error"
		print "-------------------"
		print json.dumps(resp.json(), indent=2)
		print "-------------------------------------------------------------"
		print "URL: " + url
		print "-------------------------------------------------------------"
	else:
		json_data = json.loads(resp.text)
		#print(json.dumps(resp.json(), indent=2))
	return;



args = vars(parser.parse_args())

if args['action'] == 'dump-license':
	lic_mgr_ip = args['licmgr_ip']
	lic_mgr_adm = args['licmgr_adm']
	lic_mgr_pwd = args['licmgr_pwd']
	regkey_pool_name = args['regkey_pool_name']
	
	auth_token = ligmgr_authtoken(lic_mgr_ip,lic_mgr_adm,lic_mgr_pwd)
	lm_dump_regpool(auth_token,lic_mgr_ip,regkey_pool_name)

if args['action'] == 'assign-license':
	lic_mgr_ip = args['licmgr_ip']
	lic_mgr_adm = args['licmgr_adm']
	lic_mgr_pwd = args['licmgr_pwd']
	bigip_ip = args['bigip_ip']
	bigip_adm = args['bigip_adm']
	bigip_pwd = args['bigip_pwd']
	regkey_pool = args['regkey_pool_name']

	auth_token = ligmgr_authtoken(lic_mgr_ip,lic_mgr_adm,lic_mgr_pwd)
	if args['regkey_string'] is not None:
		unused_regkey = args['regkey_string']
	else:
		unused_regkey = lm_unused_regpool(auth_token,lic_mgr_ip,regkey_pool)
	#print unused_regkey
	regkeypool_id = return_regpool_id(auth_token,lic_mgr_ip,regkey_pool)
	lm_assign_regkey(auth_token,lic_mgr_ip,bigip_ip,bigip_adm,bigip_pwd,regkeypool_id,unused_regkey)


if args['action'] == 'revoke-license':
	lic_mgr_ip = args['licmgr_ip']
	lic_mgr_adm = args['licmgr_adm']
	lic_mgr_pwd = args['licmgr_pwd']
	bigip_ip = args['bigip_ip']
	bigip_adm = args['bigip_adm']
	bigip_pwd = args['bigip_pwd']
	regkey_pool = args['regkey_pool_name']

	auth_token = ligmgr_authtoken(lic_mgr_ip,lic_mgr_adm,lic_mgr_pwd)
	regkeypool_id = return_regpool_id(auth_token,lic_mgr_ip,regkey_pool)
	key = return_device_regkey(auth_token,lic_mgr_ip,regkey_pool,bigip_ip)
	uuid = return_device_uuid(auth_token,lic_mgr_ip,regkeypool_id,key)
	lm_revoke_regkey(auth_token,lic_mgr_ip,bigip_ip,bigip_adm,bigip_pwd,regkeypool_id,uuid,key)



