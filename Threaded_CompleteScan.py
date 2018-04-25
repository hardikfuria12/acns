import os
import logging
import unicodedata
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneauth1 import identity
import novaclient.client
import neutronclient.neutron.client
import requests
from flask import Flask, request
from flask_restful import Resource, Api
import xmltodict
import json
import glob
import psycopg2
import os
import sys
import threading


class CompleteScan(threading.Thread):
    def __init__(self, namespace, hostaddress, opfilename):
        super(CompleteScan, self).__init__()
        self.namespace = namespace
        self.hostaddress = hostaddress
        self.opfilename = opfilename
		self.returnvalue=""
        #self.row = []

    def run(self):
		cmd = "sudo ip netns exec qdhcp-" + self.namespace + " nmap " + self.hostaddress + " -A -O -oX /opt/stack/completescanresult/" + str("qdhcp-" + self.namespace + "-" + self.opfilenmae) + ".xml"
		print(cmd)
		os.system(cmd)
		self.returnvalue=str("qdhcp-" + network_id[key] + "-" + temp) + ".xml" + " HAS BEEN CREATED"
		
        """cursor = self.openconnection.cursor()
        cursor.execute("SELECT * from {} ORDER BY {};".format(self.name, self.SortingColumnName))
        row1 = cursor.fetchall()
        # self.row=self.row+row1
        for r in row1:
            self.row.append(r)
        return self.row"""

def main():
	requests.packages.urllib3.disable_warnings()

	# logging.basicConfig(level=logging.DEBUG)
	logging.basicConfig(level=logging.INFO)

	LOG = logging.getLogger(__name__)

	if os.environ.get('http_proxy') or os.environ.get('https_proxy'):
			LOG.WARN("Proxy env vars set")
	username = 'admin'
	password = 'secret'
	project_name = 'admin'
	project_domain_id = 'default'
	user_domain_id = 'default'
	auth_url = 'http://192.168.56.102/identity/v3'
	auth = identity.Password(auth_url=auth_url,
							 username=username,
							 password=password,
							 project_name=project_name,
							 project_domain_id=project_domain_id,
							 user_domain_id=user_domain_id)
	sess = session.Session(auth=auth)

	# sess = session.Session(auth=auth, verify='/path/to/ca.cert')
	sess = session.Session(auth=auth, verify=False)

	netip = {}
	nova = novaclient.client.Client(2, session=sess)
	for server in nova.servers.list():
			for network_name, network in server.networks.items():
					network = "".join(network)
					network = network.encode("ascii", "ignore")
					network_name = network_name.encode("ascii", "ignore")
					netip.setdefault(network_name, [])
					netip[network_name].append(network)
	print netip

	neutc = neutronclient.neutron.client.Client('2.0', session=sess)
	networks = neutc.list_networks()
	network_id = {}
	print("Available networks for current project :")
	for i in range(0, len(networks['networks'])):
			if networks['networks'][i]['project_id'] == '159eead7308942c9b839706b8f9559c3':
					net_id_temp = networks['networks'][i]['id']
					net_name_temp = networks['networks'][i]['name']
					net_id_temp = net_id_temp.encode('ascii', 'ignore')
					net_name_temp = net_name_temp.encode('ascii', 'ignore')
					if net_name_temp in network_id:
							network_id[net_name_temp].append(net_id_temp)
					else:
							network_id[net_name_temp] = net_id_temp
	print network_id
	i=0
	threadList=list()
	for key in network_id:
			for key2 in netip:
					if key == key2:
							list = netip[key2]
							for element in list:
									i=i+1
									temp = element
									temp = temp.replace(".","-")
									threadList[i] = CompleteScan(network_id[key],element,temp)
									"""cmd = "sudo ip netns exec qdhcp-" + network_id[
											key] + " nmap " + element + " -A -O -oX /opt/stack/completescanresult/" + str(
											"qdhcp-" + network_id[key] + "-" + temp) + ".xml"
									print(cmd)
									os.system(cmd)"""
	trdlen=len(threadList)
	i=0
	for i in range(trdlen):
		threadList[i].start()
	for i in range(trdlen):
		threadList[i].join()
		

	path = r'/opt/stack/completescanresult'
	filenames = glob.glob(path + "/*.xml")
	list_dict=[]
	for file in filenames:
			d = {}
			base = os.path.basename(file)
			yyy = os.path.splitext(base)
			new_j_file_name = "/opt/stack/completescanresult/jsonfiles/" + yyy[0] + ".json"
			with open(file, "rb") as f:
					d = xmltodict.parse(f, xml_attribs="True")
					list_dict.append(d)
			with open(new_j_file_name, 'w') as jfile:
					json.dump(d, jfile, indent=4)
	path = r'/opt/stack/completescanresult/jsonfiles'
	filenames = glob.glob(path + "/*.json")
	with open("/opt/stack/completescanresult/oneforall.json", "wb") as outfile:
			for f in filenames:
					with open(f, "rb") as infile:
							outfile.write(infile.read())
							outfile.write(str.encode("\n"))
	return json.loads(json.dumps(list_dict))



if __name__ == '__main__':
	main()
	