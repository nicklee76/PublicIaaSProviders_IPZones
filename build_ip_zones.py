#!/usr/bin/env python

# __author__ = 'nicklee'
#
# Requirements:


import os, json, sys, base64, argparse, re
from datetime import datetime

try:
    import requests
except:
    sys.exit('[ERROR] no REQUESTS package found')

parser = argparse.ArgumentParser()
parser.add_argument('--debug', '-d', action='store_true', default=False,
                    help='[CoOlNiCk] Enable debug mode')
parser.add_argument('--config_file', '-c', action='store', default='./config/config.json',
                    help='[CoOlNiCk] Name of the input file.  Default is [config.json]')
args = parser.parse_args()

config = json.loads(open(args.config_file, "r").read())

####### HALO API parameters #######
api_key_id = config['HALO']['APIKeyID']
api_secret_key = config['HALO']['APISecretKey']
client_credential = api_key_id + ":" + api_secret_key
halo_api_url = config['HALO']['URL']
halo_api_version = config['HALO']['Version']
####################################

aws_ip_range_url = config['AWS']['ip_range_url']
ms_ip_range_url = config['MS']['ip_range_url']

current_directory=os.path.dirname(os.path.abspath(__file__))

ip_ranges_directory=current_directory + '/IP_ranges/'
aws_ip_ranges_directory = ip_ranges_directory + 'AWS/'
ms_ip_ranges_directory = ip_ranges_directory + 'MS/'

log_directory=current_directory + '/logs/'


def log_events(log_file, log_level, event_time, event):
    with open(log_file, 'a+') as f:
        f.write('[' + log_level + '] ' + event_time + ' ' + event + '\n')
        f.close()


def get_file_from_internet(url):
    # https://ip-ranges.amazonaws.com/ip-ranges.json
    reply = requests.request("GET", url, data=None, headers=None, verify=False)
    # print reply.status_code
    # print json.dumps(reply.json(), indent = 2, sort_keys = True)
    return reply


def build_ip_ranges_by_region(ip_ranges_json):
    # aws_region = {'syncToken': '12344567', 'us-east-1': ['10.0.0.0/24', ' 11.0.0.0.0/24'], ...}
    aws_region = {}
    aws_region['syncToken'] = ip_ranges_json['syncToken']
    for each in ip_ranges_json['prefixes']:
        if each['region'] not in aws_region.keys():
            aws_region[each['region']] = []
        aws_region[each['region']].append(each['ip_prefix'])
    return aws_region


def check_folders_and_files():
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               '[HALO] check_folders_and_files()')
    first_run = False
    if not os.path.exists(log_directory):
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Failed to find the log_directory.')
        os.mkdir(log_directory)
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Created log_directory and script execution log file.')
    if not os.path.exists(ip_ranges_directory):
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Failed to find ip_ranges_directory.')
        first_run = True
        os.mkdir(ip_ranges_directory)
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Created ip_ranges_directory.')
        os.mkdir(aws_ip_ranges_directory)
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Created aws_ip_ranges_directory.')
        reply = get_file_from_internet(aws_ip_range_url)
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Retrieved AWS IP ranges file.')
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'First time retrieving AWS ip range: ' + str(first_run))
        with open(aws_ip_ranges_directory+'aws_ip_ranges.json', 'w+') as f:
            f.write(json.dumps(reply.json(), indent = 2, sort_keys = True))
            log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                       'Wrote AWS ip ranges information to aws_ip_ranges.json file')
            f.close()

        os.mkdir(ms_ip_ranges_directory)
        log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                   'Created ms_ip_ranges_directory.')
    return first_run


###### HALO related functions #####
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


def create_halo_ip_zones(region_ip_list):
    unique_id = region_ip_list['syncToken']
    # POST https://api.cloudpassage.com/v1/firewall_zones
    for each in aws_region:
        if each.lower() != 'synctoken':
            request_body = {'firewall_zone': {'name': 'AWS-'+each+'['+unique_id+']',
                                              'ip_address': ','.join(map(str, aws_region[each]))}}
            status_code = '4xx'
            while status_code != '201':
                reply = halo_api_call('POST', halo_api_url + halo_api_version + '/firewall_zones',
                                      data=json.dumps(request_body), headers=headers)
                status_code = str(reply.status_code)


def get_ids_using_name(list, match_condition):
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               '[HALO] get_ids_using_name(%s, %s)' % (list, match_condition))
    match_dict={}
    for each in list:
        m=re.match(match_condition, each['name'])
        if m:
            log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                       '[HALO] Found IP Zone match - %s' % each)
            if each["id"] == None:
                item_id = None
                log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                           '[HALO] ID is None - %s' % each)
            else:
                item_id = each["id"]
            match_dict[each['name']] = item_id
    #print('match_dict - %s' % match_dict)
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               '[HALO] match_dict - %s' % match_dict)
    return match_dict


def delete_old_ip_zones(dict):
    #print ('delete_old_ip_zines(%s)' % dict)
    for key, value in dict.iteritems():
        status_code = '4xx'
        while status_code != '204':
            #DELETE https://api.cloudpassage.com/v1/firewall_zones/{id}
            reply = halo_api_call('DELETE', halo_api_url+halo_api_version+'/firewall_zones/'+value, data=None, headers=headers)
            if str(reply.status_code) == '204':
                #print('%s, %s' % (key, value))
                log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                           '[HALO] DELETE request SUCCESSFUL for %s(id:%s)' % (key, value))
            else:
                log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
                           '[HALO] DELETE request FAILED for %s(id:%s).  Trying Again...' % (key, value))
            status_code = str(reply.status_code)
            #print('status_code - %s' % status_code)

####################################################################################################################
first_run = check_folders_and_files()

headers = get_headers()
sp_name = 'AWS'
aws_ip_ranges = json.loads(open(aws_ip_ranges_directory + 'aws_ip_ranges.json', 'r').read())
log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               'AWS IP Ranges -\n%s' % json.dumps(aws_ip_ranges, indent = 2))

if first_run == True:
    # first time getting the AWS ip range.
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               'The first time running the script')
    aws_region = build_ip_ranges_by_region(aws_ip_ranges)
    create_halo_ip_zones(aws_region)
else:
    # not the first time getting the AWS ip range.
    #print ("Not the first time")
    log_events(log_directory + 'script_logs.log', 'DEBUG', str(datetime.now()),
               'NOT the first time running the script')
    last_aws_synctoken = aws_ip_ranges['syncToken']
    print ('Last sync token %s' % last_aws_synctoken)
    #latest_aws_synctoken = get_file_from_internet(aws_ip_range_url).json()['syncToken']
    latest_aws_synctoken = '1424718133'
    print ('Latest sync token %s' % latest_aws_synctoken)

    if int(latest_aws_synctoken) > int(last_aws_synctoken):
        #print('starting for update')
        log_events(log_directory + '/script_logs.log', 'DEBUG', str(datetime.now()),
                   'New updated AWS IP ranges.  Old syncToken:' + last_aws_synctoken + ' New syncToken:' + latest_aws_synctoken)
        # get all the firewall_zones
        reply = halo_api_call('GET', halo_api_url+halo_api_version+'/firewall_zones', data=None, headers=headers)
        #print json.dumps(reply.json()['firewall_zones'], indent = 2, sort_keys = True)
        #print ('starting to delete')
        to_be_deleted = get_ids_using_name(reply.json()['firewall_zones'], sp_name+'-(.+)\['+last_aws_synctoken+'\]')
        print('To_be_deleted - %s' % to_be_deleted)
        delete_old_ip_zones(to_be_deleted)
        print('Building the new updated ip zones')
        log_events(log_directory + '/script_logs.log', 'DEBUG', str(datetime.now()),
                   'Building the new updated IP Zones')
        aws_region = build_ip_ranges_by_region(aws_ip_ranges)
        log_events(log_directory + '/script_logs.log', 'DEBUG', str(datetime.now()),
                   'Starting to create new HALO IP Zones')
        create_halo_ip_zones(aws_region)
    else:
        log_events(log_directory + '/script_logs.log', 'DEBUG', str(datetime.now()),
                   'NO new updated AWS IP ranges.  Old syncToken:' + last_aws_synctoken + ' New syncToken:' + latest_aws_synctoken)



