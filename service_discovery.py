#!/usr/bin/env python

# __author__ = 'nicklee'
# List listening ports(with process name) & running services

import json, base64, sys, argparse, os, time
from datetime import datetime

try:
    import requests
except:
    sys.exit('[ERROR] no REQUESTS package found')


parser = argparse.ArgumentParser()
parser.add_argument('--debug', '-d', action='store_true', default=False,
                    help='[CoOlNiCk] Enable debug mode')
parser.add_argument('--config_file', '-c', action='store', default='./config/config.json',
                    help='[CoOlNiCk] Name of the input file.  Default is [./config/config.json]')
args = parser.parse_args()

config = json.loads(open(args.config_file, "r").read())

####### HALO API parameters #######
api_key_id = config['HALO']['APIKeyID']
api_secret_key = config['HALO']['APISecretKey']
client_credential = api_key_id + ":" + api_secret_key
halo_api_url = config['HALO']['URL']
halo_api_version = config['HALO']['Version']
api_url = halo_api_url+halo_api_version
####################################

current_directory=os.path.dirname(os.path.abspath(__file__))
log_directory=current_directory + '/logs/'

server_group_name = 'INSTRUCTURE-Web'


def log_events(log_file, log_level, event_time, event):
    with open(log_file, 'a+') as f:
        f.write('[' + log_level + '] ' + event_time + ' ' + event + '\n')
        f.close()


def check_folders_and_files():
    if not os.path.exists(log_directory):
        os.mkdir(log_directory)
        with open(log_directory+'script_logs.log', 'w+') as f:
            f.close()
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Created log_directory and script execution log file.')


########## HALO functions ###########

def get_headers():
    # Create headers
    user_credential_b64 = 'Basic ' + base64.b64encode(client_credential)
    reply = get_access_token(halo_api_url, '/oauth/access_token?grant_type=client_credentials',
                             {'Authorization': user_credential_b64})
    headers = {'Content-type': 'application/json', 'Authorization': 'Bearer ' + reply}
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               '[HALO] Headers created - %s' % headers)
    return headers


def get_access_token(url, query_string, headers):
    reply = requests.post(url + query_string, headers=headers, verify=False)
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               '[HALO] Access token received %s' % reply.json()['access_token'])
    return reply.json()['access_token']


def halo_api_call(method, url, **kwargs):
    reply = requests.request(method, url, data=kwargs['data'], headers=kwargs['headers'], verify=False)
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               '[HALO] HALO API call. \n\tmethod- %s\n\turl- %s\n\trequest_body-\n\t\t%s\n\theaders- %s'
               % (method, url, kwargs['data'], kwargs['headers']))
    return reply


def get_id_using_name(list, name):
    for item in list:
        if item["name"] == name:
            if item["id"] == None:
                item_id = None
            else:
                item_id = item["id"]
            return item_id


def get_value_using_key(list, key):
    key_value_dict = {}
    for each in list:
        key_value_dict[each[key]] = {'server_name': each['server_label'],
                                     'interfaces': each['interfaces'],
                                     'OS': each['kernel_name'],
                                     'running_processes': {},
                                     'listening_ports': {}
                                     }
    return key_value_dict


def get_running_processes(servers):
    # GET https://api.cloudpassage.com/v1/servers/{server_id}/processes
    servers_running_processes = {}
    running_processes=[]
    for each in servers.keys():
        processes = halo_api_call('GET', api_url + '/servers/' + each +'/processes', data = None, headers = headers)
        servers[each]['running_processes'] = processes.json()['processes']
    return servers


def get_listening_ports(servers):
    server_and_request_ids = {}

    for each in servers.keys():
        #POST https://api.cloudpassage.com/v1/servers/{server_id}/scans
        request_body = {'scan': {'module':'sca'}}
        reply = halo_api_call('POST', api_url +'/servers/' + each + '/scans', data = json.dumps(request_body), headers = headers)
        #print json.dumps(reply.json(), indent = 2, sort_keys = True)
        server_and_request_ids[each] = reply.json()['command']['id']
    #print ('Server_and_requests_IDs - %s' %server_and_request_ids)

    for each in server_and_request_ids.keys():
        #GET https://api.cloudpassage.com/v1/servers/{server_id}/commands/{id}
        scan_status = 'not_completed'
        while scan_status is not 'completed':
            reply = halo_api_call('GET', api_url + '/servers/' + each + '/commands/' + server_and_request_ids[each],
                                  data = None, headers=headers)
            #print json.dumps(reply.json(), indent = 2, sort_keys = True)
            if reply.json()['command']['status'] == 'completed':
                #time.sleep(5)
                scan_status = 'completed'
                #GET https://api.cloudpassage.com/v1/servers/{server_id}/sca
                reply = halo_api_call('GET', api_url + '/servers/' + each + '/sca', data = None, headers = headers)
                #print json.dumps(reply.json(), indent = 2, sort_keys = True)
                servers[each]['listening_ports'] = reply.json()['scan']['findings']
    return servers


######################################################################################################################

check_folders_and_files()

headers = get_headers()

# list server groups
# GET https://api.cloudpassage.com/v1/groups
server_groups = halo_api_call('GET', api_url+'/groups', data = None, headers = headers)
#print json.dumps(reply.json(), indent = 2, sort_keys = True)

server_group_id = get_id_using_name(server_groups.json()['groups'], server_group_name)
#print server_group_id

# GET https://api.cloudpassage.com/v1/groups/{group_id}/servers
servers = halo_api_call('GET', api_url + '/groups/' + server_group_id + '/servers', data = None, headers = headers)
#print json.dumps(servers.json(), indent = 2, sort_keys = True)

# servers_information = { server_id :{'server_name': xxxx}, 'interfaces':[{...}], 'OS': 'Linux'}
servers_information = get_value_using_key(servers.json()['servers'], 'id')
#print servers_information

# servers_information = { server_id :{'server_name': xxxx, 'interfaces':[{...}], 'OS': 'Linux', 'running_processes': [{}]}}
servers_information = get_running_processes(servers_information)
#print servers_information

# Get listening ports
servers_information = get_listening_ports(servers_information)
print json.dumps(servers_information, indent = 2, sort_keys = True)

