# Copyright (C) 2014-2015 Kevin Breen (http://techanarchy.net)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import sys
import json
import string
from zipfile import ZipFile
from cStringIO import StringIO

#Non Standard Imports
from Crypto.Cipher import ARC4

#Helper Functions Go Here

def string_print(line):
    try:
        return filter(lambda x: x in string.printable, str(line))
    except:
        return line

####RC4 Cipher ####	
def decrypt_RC4(enckey, data):
	cipher = ARC4.new(enckey) # set the ciper
	return cipher.decrypt(data) # decrypt the data

def parse_config(raw_config):
    config_dict = {}
    if 'JSocket' in raw_config:
        config = json.loads(raw_config)
        for k, v in config.iteritems():
            config_dict[k] = v
    else:
        for line in raw_config.split('\n'):
            if line.startswith('<entry key'):
                config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
    return config_dict

def extract_config(file_name):
    enckey = coded_jar = False
    config = None
    try:
        with ZipFile(file_name, 'r') as zip:
            for name in zip.namelist():
                if name == 'ID':
                    pre_key = zip.read(name)
                    enckey = '{0}H3SUW7E82IKQK2J2J2IISIS'.format(pre_key)
                elif name == 'a.txt':
                    pre_key = zip.read(name)
                    enckey = '{0}{1}{0}{1}a'.format('plowkmsssssPosq34r', pre_key)
                if name == 'MANIFEST.MF':
                    coded_jar = zip.read(name)
                elif name == 'b.txt':
                    coded_jar = zip.read(name)

        if enckey and coded_jar:
            decoded_data = decrypt_RC4(enckey, coded_jar)
            decoded_jar = StringIO(decoded_data)
        else:
            return

        with ZipFile(decoded_jar) as zip:
            for name in zip.namelist():
                if name in ['config.xml', 'org/jsocket/resources/config.json']:
                    raw_config = zip.read(name)
        config = parse_config(raw_config)
    except:
        pass
    return config
        
