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

status=""
class CompleteScan(threading.Thread):
    def __init__(self, namespace, hostaddress, opfilename1,opfilename2,override,typeScan):
        super(CompleteScan, self).__init__()
        self.namespace = namespace
        self.hostaddress = hostaddress
        self.opfilename1 = opfilename1
		self.override=override
		self.typeScan=typeScan
	self.returnvalue=""

    def run(self):
		global status 
		scan_ids = ["8715c877-47a0-438d-98a3-27c7a6ab2196", "085569ce-73ed-11df-83c3-002264764cea",
					  "daba56c8-73ec-11df-a475-002264764cea",
					  "698f691e-7489-11df-9d8c-002264764cea", "708f25c4-7489-11df-8094-002264764cea",
					  "74db13d6-7489-11df-91b9-002264764cea", "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
					  "bbca7412-a950-11e3-9109-406186ea4fc5"]
		cmd = "sudo ip netns exec qdhcp-" + self.namespace + " nmap " + self.hostaddress + " -A -O -oX /opt/stack/completescanresult/" + str("qdhcp-" + self.namespace + "-" + self.opfilename1) + ".xml"
		print(cmd)
		os.system(cmd)
		self.returnvalue=str("qdhcp-" + self.namespace + "-" + self.opfilename1) + ".xml" + " HAS BEEN CREATED"
		print(self.returnvalue)
		return self.returnvalue
		location = "/opt/stack/vulnerabilityscanresult/"
		loc_json = "/opt/stack/vulnerabilityscanresult/jsonfiles/"
		host_var = self.hostaddress.replace(".","-")
		location = location + self.namespace[-7:] +host_var[-6:] + str(self.typeScan)
		loc_json = loc_json + self.namespace[-7:] +host_var[-6:] + str(self.typeScan)
		file_var = location+".xml"
		file_var_json = location +".json"
		
		f1 = open(file_var, "w")
		user="admin"
		password="admin"
		self.typeScan=str(self.typeScan)
		self.opfilename2 = self.opfilename2 + host_var[-6:]
		print "Target is this " + self.opfilename2
		step0 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', self.namespace, '-u', user, '-w', password,
								  '--xml=<create_target><name>' + self.opfilename2 + '</name><hosts>' + self.hostaddress + '</hosts></create_target>'],
								 stdout=subprocess.PIPE)
		for line in step0.stdout.readlines():
			root = xt.fromstring(line)
		if root.attrib['status_text'] == "Target exists already":
			print "self.opfilename2 exist"
			step1 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', self.namespace, '-u', user, '-w', password, '-T'],
									 stdout=subprocess.PIPE)
			for line in step1.stdout.readlines():
				tmp = line.split()
				if tmp[1] == self.opfilename2:
					if self.override == "yes":
						print tmp[0]
						step2 = subprocess.Popen(
							['sudo', 'omp', 'ip', 'netns', 'exec', self.namespace, '-u', user, '-w', password, '-iX',
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
							['sudo', 'omp', 'ip', 'netns', 'exec', self.namespace, '-u', user, '-w', password,
							 '--xml=<create_target><name>' + self.opfilename2 + '</name><hosts>' + self.hostaddress + '</hosts></create_target>'],
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
		step3 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', self.namespace, '-u', user, '-w', password,
								  '--xml=<create_task><name>' + self.opfilename2 + '-' + str(self.typeScan) + '</name><config id="' +
								  scan_ids[int(self.typeScan)] + '"/><target id="' + target_id + '"/></create_task>'],
								 stdout=subprocess.PIPE)
		for line in step3.stdout.readlines():
			root = xt.fromstring(line)
		if root.attrib['status_text'] == "OK, resource created":
			task_id = root.attrib['id']
			print "Task created with id=", task_id
		else:
			print "error in creating task. Exiting"
			sys.exit()
		step4 = subprocess.Popen(['sudo', 'omp', 'ip', 'netns', 'exec', self.namespace, '-u', user, '-w', password,
								  '--xml=<start_task task_id="' + task_id + '"/>'], stdout=subprocess.PIPE)
		for line in step4.stdout.readlines():
			print line
			root = xt.fromstring(line)

		for value in root.iter('report_id'):
			report_id = value.text
			print "report generated will have id=", report_id
		while True: 
			proc5 = subprocess.Popen(['omp', '-u', user, '-w', password, '-G'], stdout=subprocess.PIPE)
			for line in proc5.stdout.readlines():
				tmp = line.split()
				if tmp[0] == task_id:
						if tmp[1] == "Running":
								print tmp[1], tmp[2]
						else:
								status = tmp[1]
								print tmp[1]
			if status == "Done":
				break
			else:
				sleep(5)
		print "Report id= ", report_id
		step4 = subprocess.Popen(['omp', '-u', user, '-w', password, '-iX', '<get_reports report_id="' + report_id + '" details="1"/>'],stdout=subprocess.PIPE)
		for line in step4.stdout.readlines():
			print >> f1, line.rstrip()
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
							list1 = netip[key2]
							for element in list1:	
									tt = network_id[key]
									tt = tt[-7:]
									temp = element
									temp = temp.replace(".","-")
									override="no"
									threadList.append(CompleteScan(network_id[key],element,temp,tt,override,0))
									i=i+1	
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
	