#!/usr/bin/env python

# __author__ = 'nicklee'

# http://www.cloudpassage.com
#
# Description: List listening ports(with process name) & running services for each workload
#
# Requirements: This script requires following in order for this script to work
#   Packages:       requests
#   File(s):        Configuration file called "config.json" file under the '/config' directory (or
#                   use command line argument - refer to below)
#
# Command line / Terminal arguments: The script would take 2 arguments from the terminal / command line.
#   --debug         Optional (default = False).  Enable debug mode for more information on what is happening.
#   --config_file   Optional (default = './config/config.json').  HALO and other related information to run the scripts
#   --server_group  Optional (default = 'Service_Discovery'.  Name of the HALO server group to use


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
parser.add_argument('--server_group', '-s', action='store', default='Service_Discovery',
                    help='[CoOlNiCk] Name of the HALO server group to use.  Default is [Service_Discovery]')
args = parser.parse_args()

config = json.loads(open(args.config_file, "r").read())

server_group_name = args.server_group

####### HALO API parameters #######
api_key_id = config['HALO']['APIKeyID']
api_secret_key = config['HALO']['APISecretKey']
client_credential = api_key_id + ":" + api_secret_key
halo_api_url = config['HALO']['URL']
halo_api_version = config['HALO']['Version']
api_url = halo_api_url+halo_api_version
####################################

####### Known process for each TCP / UDP ports ########
known_linux_ports = config['LinuxPortsProcesses']

screen_width = 145

current_directory=os.path.dirname(os.path.abspath(__file__))
log_directory=current_directory + '/logs/'


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
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               'get_id_using_name(%s, %s)' % (list, name))
    for item in list:
        if item["name"] == name:
            if item["id"] == None:
                item_id = None
            else:
                item_id = item["id"]
            return item_id


def get_value_using_key(list, key):
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               'get_value_using_key(%s, %s)' % (list, key))
    key_value_dict = {}
    for each in list:
        if each['server_label'] is None:
            # server_label was not used.  Using the server ID (HALO record) instead.
            server_name = each['hostname']
        else:
            server_name = each['server_label']
        key_value_dict[each[key]] = {'server_name': server_name,
                                     'interfaces': each['interfaces'],
                                     'OS': each['kernel_name'],
                                     'running_processes': {},
                                     'listening_ports': {},
                                     'server_ID': each['id']
                                     }
    return key_value_dict


def get_running_processes(servers):
    # GET https://api.cloudpassage.com/v1/servers/{server_id}/processes
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               'get_running_process(%s)' % servers)
    for each in servers.keys():
        processes = halo_api_call('GET', api_url + '/servers/' + each +'/processes', data = None, headers = headers)
        servers[each]['running_processes'] = processes.json()['processes']
    return servers


def get_listening_ports(servers):
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               'get_listening_ports(\n%s\n)' % json.dumps(servers, indent = 2, sort_keys = True))
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
            time.sleep(5)
    return servers


######################################################################################################################

check_folders_and_files()

headers = get_headers()

# list server groups
# GET https://api.cloudpassage.com/v1/groups
server_groups = halo_api_call('GET', api_url+'/groups', data = None, headers = headers)
log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
           'server_groups\n%s' % json.dumps(server_groups.json(), indent = 2, sort_keys = True))
#print json.dumps(reply.json(), indent = 2, sort_keys = True)

server_group_id = get_id_using_name(server_groups.json()['groups'], server_group_name)
log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
           'server_group_id - %s' % server_group_id)
#print server_group_id

# GET https://api.cloudpassage.com/v1/groups/{group_id}/servers
servers = halo_api_call('GET', api_url + '/groups/' + server_group_id + '/servers', data = None, headers = headers)
log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
           'servers - %s' % servers)
#print json.dumps(servers.json(), indent = 2, sort_keys = True)

# servers_information = { server_id :{'server_name': xxxx}, 'interfaces':[{...}], 'OS': 'Linux'}
servers_information = get_value_using_key(servers.json()['servers'], 'id')
log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
           'servers_information\n\t%s' % json.dumps(servers_information, indent = 2, sort_keys = True))
#print servers_information

# servers_information = { server_id :{'server_name': xxxx, 'interfaces':[{...}], 'OS': 'Linux', 'running_processes': [{}]}}
servers_information = get_running_processes(servers_information)
log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
           'servers_information\n%s' % json.dumps(servers_information, indent = 2, sort_keys = True))
#print servers_information

# Get listening ports
servers_information = get_listening_ports(servers_information)
log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
           'servers_information\n%s' % json.dumps(servers_information, indent = 2, sort_keys = True))
print json.dumps(servers_information, indent = 2, sort_keys = True)


print('\n')
print('=' * screen_width)
print('{0:70}{1:15}{2:20}{3:30}').format('Server','Listening', 'Running', 'Known')
print('{0:25}{1:35}{2:10}{3:15}{4:20}{5:30}{6:15}').format('Label', 'Server ID', 'OS', 'Ports', 'Process', 'Process', 'Abnormal')
print('-' * screen_width)
for server in servers_information.keys():
    listening_ports = {}
    listening_ports_processes = []
    running_process = []
    for each in servers_information[server]['listening_ports']:
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   '======== Listening Ports (%s)=============' % server)
        #print json.dumps(each['details'], indent = 2, sort_keys = True)
        for port in each['details']:
            if port['actual'] is not None:
                listening_ports[port['actual']] = port['bound_process']
                if port['bound_process'] not in listening_ports_processes:
                    listening_ports_processes.append(port['bound_process'])
    #print listening_ports
    for each in listening_ports.keys():
        each_splitted = each.split('/')
        # '22/TCP'
        abnormal_process = "!! NO MATCH !!"
        if listening_ports[each] in known_linux_ports[each_splitted[1]][each_splitted[0]]:
            abnormal_process = "OK"
        print('{0:25}{1:35}{2:10}{3:15}{4:20}{5:30}{6:15}').format(servers_information[server]['server_name'],
                                                       servers_information[server]['server_ID'],
                                                       servers_information[server]['OS'],
                                                       each,
                                                       listening_ports[each],
                                                       known_linux_ports[each_splitted[1]][each_splitted[0]],
                                                       abnormal_process)

    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               '======== Running Processes (%s)=============' % server)
    for each in servers_information[server]['running_processes']:
        #print json.dumps(each, indent = 2, sort_keys = True)
        #print ('%s  %s' % (each['process_name'], running_process))
        if each['process_name'] not in listening_ports_processes:
            running_process.append(each['process_name'])
        #print ('%s\n' % running_process)

    for each in running_process:
        print('{0:25}{1:35}{2:10}{3:15}{4:20}').format(servers_information[server]['server_name'],
                                                       servers_information[server]['server_ID'],
                                                       servers_information[server]['OS'],
                                                       'N/A',
                                                       each)

    print('-' * screen_width)

print('[CoOlNiCk] - DONE')