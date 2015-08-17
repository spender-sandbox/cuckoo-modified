# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess
import json
import sys
import urllib2
import urllib
import time
import socket
import struct
import copy

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report 

log = logging.getLogger(__name__)

class Moloch(Report):

    """Moloch processing."""
    def cmd_wrapper(self,cmd):
        #print("running command and waiting for it to finish %s" % (cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout,stderr = p.communicate()
        return (p.returncode, stdout, stderr)
    
    # This was useful http://blog.alejandronolla.com/2013/04/06/moloch-capturing-and-indexing-network-traffic-in-realtime/
    def update_tags(self,tags,expression):
        auth_handler = urllib2.HTTPDigestAuthHandler()
        auth_handler.add_password(self.MOLOCH_REALM, self.MOLOCH_URL, self.MOLOCH_USER, self.MOLOCH_PASSWORD)
        opener = urllib2.build_opener(auth_handler)
        data = urllib.urlencode({'tags' : tags})
        qstring = urllib.urlencode({'date' : "-1",'expression' : expression})
        TAG_URL = self.MOLOCH_URL + 'addTags?' + qstring
        try:
            response = opener.open(TAG_URL,data=data)
            if response.code == 200:
                plain_answer = response.read()
                json_data = json.loads(plain_answer)
            time.sleep(.5)
        except Exception, e:
            raise e

        
    def run(self,results):
        """Run Moloch to import pcap
        @return: nothing 
        """
        self.key = "moloch"
        self.alerthash ={}
        self.MOLOCH_CAPTURE_BIN = self.options.get("capture", None)
        self.MOLOCH_CAPTURE_CONF = self.options.get("captureconf",None)
        self.CUCKOO_INSTANCE_TAG = self.options.get("node",None)
        self.MOLOCH_USER = self.options.get("user",None)
        self.MOLOCH_PASSWORD = self.options.get("pass",None) 
        self.MOLOCH_REALM = self.options.get("realm",None)
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.MOLOCH_URL = self.options.get("base",None)

        m = re.search(r"/(?P<task_id>\d+)/dump.pcap$",self.pcap_path)
        if m == None:
            log.warning("Unable to find task id from %s" % (self.pcap_path))
            return results  
        else:
            self.task_id = m.group("task_id")

        if not os.path.exists(self.MOLOCH_CAPTURE_BIN):
            log.warning("Unable to Run moloch-capture: BIN File %s Does Not Exist" % (self.MOLOCH_CAPTURE_BIN))
            return
        
        if not os.path.exists(self.MOLOCH_CAPTURE_CONF):
            log.warning("Unable to Run moloch-capture Conf File %s Does Not Exist" % (self.MOLOCH_CAPTURE_CONF))
            return         
        try:
            cmd = "%s -c %s -r %s -n %s -t %s:%s" % (self.MOLOCH_CAPTURE_BIN,self.MOLOCH_CAPTURE_CONF,self.pcap_path,self.CUCKOO_INSTANCE_TAG,self.CUCKOO_INSTANCE_TAG,self.task_id)
        except Exception,e:
            log.warning("Unable to Build Basic Moloch CMD: %s" % e)
             
        if self.task["category"] == "file":
            try:
                if self.task["category"] == "file":
                    if results.has_key('virustotal'):
                        for key in results["virustotal"]["scans"]:
                            if results["virustotal"]["scans"][key]["result"]:
                                cmd = cmd + " -t \"VT:%s:%s\"" % (key,results["virustotal"]["scans"][key]["result"])
            except Exception,e:
                log.warning("Unable to Get VT Results For Moloch: %s" % e)


            if results["target"]["file"].has_key("md5") and results["target"]["file"]["md5"]:
                cmd = cmd + " -t \"md5:%s\"" % (results["target"]["file"]["md5"])
            if results["target"]["file"].has_key("sha1") and results["target"]["file"]["sha1"]:
                cmd = cmd + " -t \"sha1:%s\"" % (results["target"]["file"]["sha1"])
            if results["target"]["file"].has_key("sha256") and results["target"]["file"]["sha256"]:
                cmd = cmd + " -t \"sha256:%s\"" % (results["target"]["file"]["sha256"])
            if results["target"]["file"].has_key("sha512") and results["target"]["file"]["sha512"]:
                cmd = cmd + " -t \"sha512:%s\"" % (results["target"]["file"]["sha512"])
            if results["target"]["file"].has_key("clamav") and results["target"]["file"]["clamav"]:
                cmd = cmd + " -t \"clamav:%s\"" % (results["target"]["file"]["clamav"])
            if results["static"].has_key("pe_imphash") and results["static"]["pe_imphash"]:
                cmd = cmd + " -t \"pehash:%s\"" % (results["static"]["pe_imphash"])

        try:                   
            ret,stdout,stderr = self.cmd_wrapper(cmd)
            if ret == 0:
               log.warning("moloch: imported pcap %s" % (self.pcap_path))
            else:
                log.warning("moloch-capture returned a Exit Value Other than Zero %s" % (stderr))
        except Exception,e:
            log.warning("Unable to Run moloch-capture: %s" % e)

        time.sleep(5)
         
        if results.has_key('suricata'):
           if results["suricata"].has_key("alerts"):
               for alert in results["suricata"]["alerts"]:
                   proto = alert['protocol']
                   if proto:
                       tmpdict = {}
                       cproto = ""
                       if proto == "UDP" or proto == "TCP" or proto == "6" or proto == "17":
                           tmpdict['src'] = alert['srcip']
                           tmpdict['sport'] = alert['srcport']
                           tmpdict['dst'] = alert['dstip']
                           tmpdict['dport'] = alert['dstport']
                           if proto == "UDP" or proto == "17":
                               tmpdict['cproto'] = "udp"
                               tmpdict['nproto'] = 17
                           elif proto == "TCP" or proto == "6":
                               tmpdict['cproto'] = "tcp"
                               tmpdict['nproto'] = 6
                           tmpdict['expression'] = "ip==%s && ip==%s && protocols==%s && port==%s && port==%s && tags==\"%s:%s\"" % (tmpdict['src'],tmpdict['dst'],tmpdict['cproto'],tmpdict['sport'],tmpdict['dport'],self.CUCKOO_INSTANCE_TAG,self.task_id)
                           tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src']))[0] + tmpdict['sport'] + struct.unpack('!L',socket.inet_aton(tmpdict['dst']))[0] + tmpdict['dport']
                       elif proto == "ICMP" or proto == "1":
                           tmpdict['src'] = alert['srcip']
                           tmpdict['dst'] = alert['dstip']
                           tmpdict['cproto'] = "icmp"
                           tmpdict['nproto'] = 1
                           tmpdict['expression'] = "ip==%s && ip==%s && protocols==%s && tags==\"%s:%s\"" % (tmpdict['src'],tmpdict['dst'],tmpdict['cproto'],self.CUCKOO_INSTANCE_TAG,self.task_id)
                           tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src']))[0] + struct.unpack('!L',socket.inet_aton(tmpdict['dst']))[0]

                       if self.alerthash.has_key(tmpdict['hash']):
                           if alert['sid'] not in self.alerthash[tmpdict['hash']]['sids']:
                               self.alerthash[tmpdict['hash']]['sids'].append("sid:%s" % (alert['sid']))
                       else:
                           self.alerthash[tmpdict['hash']] = copy.deepcopy(tmpdict)
                           self.alerthash[tmpdict['hash']]['sids']=[]
                           self.alerthash[tmpdict['hash']]['sids'].append("sid:%s" % (alert['sid']))
               for entry in self.alerthash:
                   tags = ','.join(map(str,self.alerthash[entry]['sids']))
                   if tags:
                       self.update_tags(tags,self.alerthash[entry]['expression'])

           if results["suricata"].has_key("files"):
               for entry in results["suricata"]["files"]:
                   if  entry.has_key("file_info"):
                       if entry["file_info"]["clamav"]:
                           tags = "clamav:%s" % (entry["file_info"]["clamav"])
                           expression = "ip==%s && ip==%s && port==%s && port==%s && tags==\"%s:%s\" && protocols==tcp" % (entry["srcip"],entry["dstip"],entry["sp"],entry["dp"],self.CUCKOO_INSTANCE_TAG,self.task_id)
                           self.update_tags(tags,expression)
        return {} 
