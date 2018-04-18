import sys
import subprocess
import argparse
import xml.etree.ElementTree as xt
from time import sleep
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

app = Flask(__name__)
api = Api(app)

#f1 = open("report.xml", "w")


status=""
class VulnScan(Resource):
	def get(self):
		requests.packages.urllib3.disable_warnings()

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
		#i=0
		for key in network_id:
			for key2 in netip:
				if key == key2:
					list = netip[key2]
					for element in list:
						for i in range(7):
							tt = network_id[key]
							tt = tt[-7:]
							override = "no"
							self.openvasScan(network_id[key], element, tt, override,i)
		#return self.oneforalljson()
		return "vuln scan completed see your xml files"


		

	def openvasScan(self,namespace,host,target,override,scantype):
		print namespace
		print host
		print target
		print override
		print scantype

		scan_ids = ["8715c877-47a0-438d-98a3-27c7a6ab2196", "085569ce-73ed-11df-83c3-002264764cea",
					  "daba56c8-73ec-11df-a475-002264764cea",
					  "698f691e-7489-11df-9d8c-002264764cea", "708f25c4-7489-11df-8094-002264764cea",
					  "74db13d6-7489-11df-91b9-002264764cea", "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
					  "bbca7412-a950-11e3-9109-406186ea4fc5"]


		location = "/opt/stack/vulnerabilityscanresult/"
		loc_json = "/opt/stack/vulnerabilityscanresult/jsonfiles/"
		host_var = host.replace(".","-")
		location = location + namespace[-7:] +host_var[-6:] + str(scantype)
		loc_json = loc_json + namespace[-7:] +host_var[-6:] + str(scantype)
		file_var = location+".xml"
		file_var_json = location +".json"
		
		f1 = open(file_var, "w")
		user="admin"
		password="admin"
		scantype=str(scantype)
		target = target + host_var[-6:]
		print "Target is this " + target
		step0 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', namespace, '-u', user, '-w', password,
								  '--xml=<create_target><name>' + target + '</name><hosts>' + host + '</hosts></create_target>'],
								 stdout=subprocess.PIPE)
		for line in step0.stdout.readlines():
			root = xt.fromstring(line)
		if root.attrib['status_text'] == "Target exists already":
			print "target exist"
			step1 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', namespace, '-u', user, '-w', password, '-T'],
									 stdout=subprocess.PIPE)
			for line in step1.stdout.readlines():
				tmp = line.split()
				if tmp[1] == target:
					if override == "yes":
						print tmp[0]
						step2 = subprocess.Popen(
							['sudo', 'omp', 'ip', 'netns', 'exec', namespace, '-u', user, '-w', password, '-iX',
							 '<delete_target target_id="' + tmp[0] + '"/>'], stdout=subprocess.PIPE)
						for line in step2.stdout.readlines():
							print "line is ", line
							root = xt.fromstring(line)
							print root.attrib['status_text']
						if root.attrib['status_text'] == "OK":
							pass
						else:
							print "error. Try a different name."
							sys.exit()
						# create target
						step0 = subprocess.Popen(
							['sudo', 'omp', 'ip', 'netns', 'exec', namespace, '-u', user, '-w', password,
							 '--xml=<create_target><name>' + target + '</name><hosts>' + host + '</hosts></create_target>'],
							stdout=subprocess.PIPE)
						for line in step0.stdout.readlines():
							root = xt.fromstring(line)
							target_id = root.attrib['id']
							print "Target created with id=", target_id
					else:
						target_id = tmp[0]
						print "Target created with id=", target_id
		else:
			target_id = root.attrib['id']
			print "Target created with id=", target_id
		step3 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', namespace, '-u', user, '-w', password,
								  '--xml=<create_task><name>' + target + '-' + str(scantype) + '</name><config id="' +
								  scan_ids[int(scantype)] + '"/><target id="' + target_id + '"/></create_task>'],
								 stdout=subprocess.PIPE)
		for line in step3.stdout.readlines():
			root = xt.fromstring(line)
		if root.attrib['status_text'] == "OK, resource created":
			task_id = root.attrib['id']
			print "Task created with id=", task_id
		else:
			print "error in creating task. Exiting"
			sys.exit()
		step4 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', namespace, '-u', user, '-w', password,
								  '--xml=<start_task task_id="' + task_id + '"/>'], stdout=subprocess.PIPE)
		for line in step4.stdout.readlines():
			print line
			root = xt.fromstring(line)

		for value in root.iter('report_id'):
			report_id = value.text
			print "report generated will have id=", report_id


		while True:
			self.check_complete(task_id)
			if status == "Done":
				break
			else:
				sleep(5)
		print "Report id= ", report_id
		step4 = subprocess.Popen(['omp', '-u', user, '-w', password, '-iX', '<get_reports report_id="' + report_id + '" details="1"/>'],stdout=subprocess.PIPE)
		for line in step4.stdout.readlines():
			print >> f1, line.rstrip()

	def check_complete(self,task_id):
		global status
		task_id=task_id
		user ="admin"
		password = "admin"
		proc5 = subprocess.Popen(['omp', '-u', user, '-w', password, '-G'], stdout=subprocess.PIPE)
		for line in proc5.stdout.readlines():
				tmp = line.split()
				if tmp[0] == task_id:
						if tmp[1] == "Running":
								print tmp[1], tmp[2]
						else:
								status = tmp[1]
								print tmp[1]
"""	def oneforalljson(self):
		path = r'/opt/stack/vulnerabilityscanresult/jsonfiles/'
		filenames = glob.glob(path + "*.json")
		with open("/opt/stack/vulnerabilityscanresult/oneforall.json", "wb") as outfile:
			for f in filenames:
				with open(f, "rb") as infile:
					outfile.write(infile.read())
					outfile.write(str.encode("\n"))
		with open("/opt/stack/vulnerabilityscanresult/oneforall.json") as data_file:
			return json.load(data_file) """
			
			
								
api.add_resource(VulnScan, '/VulnScan',methods=['GET'])
if __name__ == "__main__":
	app.run(host='0.0.0.0', port=7000, debug=True)
