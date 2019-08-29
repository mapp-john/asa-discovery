import os
import re
import time
import jinja2
import json
import shutil
import socket
import random
import requests 
import logging
import netmiko
import paramiko
import traceback
from threading import Thread
import subprocess
import queue as queue
from datetime import datetime
from netmiko.ssh_exception import *
from zipfile import ZipFile, ZIP_DEFLATED
from EmailModule import emailHTMLWithRenamedAttachment



def MONGO_POST(post_data,device,outputList,counter,date):
    date = date.replace(' ','_').replace(':','_')
    headers = {'Content-Type':"application/json"}
    url = f'https://mongo-api.domain.com/api/v1.0/FIREWALL_INV_{date}' 
    try:
        r = None
        print("Posting to --> "+url+"\n")
        # REST call with SSL verification turned off:
        r = requests.post(url, json=post_data, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        print(status_code)
        print(resp) 

        if (status_code == 200):
            r.close()
            resp = r.json()
            ACK = resp["acknowledged"]
            if ACK == True : 
                Results = f"Item successfully inserted into FIREWALL_INV_{date}"
                ID = resp["_id"]
            else : 
                Results = f"Item failed to be inserted into FIREWALL_INV_{date}"
                ID = "None"
            # Save To File 
            outputList.put("["+str(counter)+"] POST successful\n")
            outputList.put("["+str(counter)+"] Device: "+device+"\n")
            outputList.put("["+str(counter)+"] Results: "+Results+"\n")
            outputList.put("["+str(counter)+"] ID: "+ID+"\n")
        elif (status_code == 401):
            r.close()
            outputList.put("["+str(counter)+"] Authentication Failure -->  "+url+"\n")
            print("Authentication Failure -->  "+url+"\n")
        else:
            r.close()
            r.raise_for_status()
            outputList.put("["+str(counter)+"] Error occurred in POST..."+device+" "+url+"\n"+str(post_data)+"\n")
            print(traceback.format_exc())
    except:
         r.close()
         outputList.put("["+str(counter)+"] Error occurred in POST..."+device+" "+url+"\n"+str(post_data)+"\n")
         print(traceback.format_exc())
         
   
    # End 
    finally:
        if r : r.close()



def COMMANDS(username,password,sfr_username,sfr_password,ips_username,ips_password,counter,device_type,devices,deviceList,outputList,date,csvList,jsonList):
    while not deviceList.empty():
        device = deviceList.get_nowait()
        
        hostname = None
        IP_address = None
        
        # Performing nslookup on device name
        if re.match(r'\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b',device):
            IP_address = device
            try:
                hostname = socket.gethostbyaddr(device)[0]
            except:
                hostname = None
        else:
            hostname = socket.gethostbyaddr(device)[0]
            try:
                IP_address = socket.gethostbyaddr(device)[-1][0]
            except:
                IP_address = None
        

        try:
            # Connection Break
            counter = len(devices)-deviceList.qsize()
            print(f'\n[{str(counter)}] Connecting to: {device}\n')
            # Connection Handler
            connection = netmiko.ConnectHandler(ip=IP_address, device_type=device_type, username=username, password=password, secret=password, global_delay_factor=5)

            # Get device name from config
            if not hostname:
                show_output = connection.send_command('sh run hostname').strip()
                hostname = show_output.split()[-1]
                # Domain
                show_output = connection.send_command('sh run domain').strip()
                domain = show_output.split()[-1]
                if not domain == None: 
                    hostname = f'{hostname}.{domain}'
                
            
            # Context Mode
            show_output = connection.send_command('sh mode').strip()
            asa_contextmode = show_output.split()[-1]
            
            # Firewall mode
            show_output = connection.send_command('sh firewall').strip()
            asa_firewallmode = show_output.split()[-1]
            
            status = 'Successful'
            asa_serial = None
            asa_version = None
            asa_asdm = None
            cluster_uptime = None
            # Serial
            show_output = connection.send_command('sh ver | in Serial|Software|Device Manager|up').strip()
            for line in show_output.splitlines():
                if 'Serial' in line:
                    asa_serial = line.split()[-1].strip()
                elif 'Software' in line and 'context' in line:
                    asa_version = line.split()[-2].strip()
                elif 'Software' in line:
                    asa_version = line.split()[-1].strip()
                elif 'Device Manager' in line and 'context' in line:
                    asa_asdm = line.split()[-2].strip()
                elif 'Device Manager' in line:
                    asa_asdm = line.split()[-1].strip()
                elif 'failover cluster' in line:
                    cluster_uptime = line.split('failover cluster up')[-1].strip()
                elif 'up' in line:
                    uptime = line.split('up')[-1].strip()
                    
            ssd = None
            show_output = connection.send_command('sh inven').strip().splitlines()
            for index in range(len(show_output)):
                if '"Chassis"' in show_output[index]:
                    asa_chassis = show_output[index +1].split()[-1]
                    asa_model = show_output[index +1].split()[1]
                elif 'Storage Device' in show_output[index]:
                    ssd = 'SSD Installed'
            
            
            asa_serial_failover = None
            asa_chassis_failover = None
            # Failover Serial
            show_output = connection.send_command('sh failover').strip()
            failover_status = show_output.splitlines()[0].split()[-1]
            if 'On' in failover_status:
                show_output = connection.send_command('failover exec mate sh ver | in Serial').strip()
                for line in show_output.splitlines():
                    if 'Serial' in line:
                        asa_serial_failover = line.split()[-1]
                    else:
                        asa_serial_failover = None
                    show_output = connection.send_command('failover exec mate sh inven').strip().splitlines()
                    for index in range(len(show_output)):
                        if '"Chassis"' in show_output[index]:
                            asa_chassis_failover = show_output[index +1].split()[-1]

            # ASA Dict
            asa_dict = {
                    'date': date,
                    'hostname': hostname,
                    'status': status,
                    'ip_address': IP_address,
                    'model': asa_model,
                    'context_mode':asa_contextmode,
                    'firewall_mode':asa_firewallmode,
                    'chassis':asa_chassis,
                    'ssd': ssd,
                    'asa_serial':asa_serial,
                    'asa_version':asa_version,
                    'asa_asdm':asa_asdm,
                    'failover_status':failover_status,
                    'chassis_failover':asa_chassis_failover,
                    'asa_serial_failover':asa_serial_failover,
                    'uptime':uptime,
                    'cluster_uptime':cluster_uptime,
                    }
            
            if asa_contextmode == 'multiple':
                contextdict = {}
                output = connection.send_command_timing('changet sys').strip()
                if output.startswith('Command not valid'):
                    pass
                else:
                    output = connection.send_command('sh run context').strip()
                    for line in output.splitlines():
                      if line.startswith('admin'):
                        contextdict[line.split()[-1]]= {'admin':'YES'}
                      elif line.startswith('context'):
                        if contextdict.get(line.split()[-1]):
                          pass
                        else:
                          contextdict[line.split()[-1]] = {'admin':'NO'} 
                    for context in contextdict.keys():
                        if asa_firewallmode == 'Transparent':
                            try:
                                connection.send_command_timing(f'changet cont {context}')   
                                show_output = connection.send_command('sh ip | b Management System IP Address').splitlines()
                                ip = show_output[1].split()[-2]
                                contextdict[context]["ip_address"] = ip
                            except:
                                pass
                        else:
                            try:
                                connection.send_command_timing('changet cont '+context)   
                                show_output = connection.send_command('sh run ssh | in ssh 10.').splitlines()
                                interface = show_output[0].split()[-1]
                                show_output = connection.send_command(f'sh ip | in {interface}').splitlines()
                                ip = show_output[0].split()[-3]
                                contextdict[context]["ip_address"] = ip
                            except:
                                pass
                    asa_dict.update({'contexts': contextdict})

            # Default Dict
            ips_dict = {
                    'type': None,
                    'version': None
                    }

            ips_type = None
            ip_address = None
            ips_status = None
            version = None
            vrt = None
            manager = None
            # SFR or IPS and Version
            show_output = connection.send_command('sh module | in IPS|ips|sfr').strip()
            if ' sfr ' in show_output:
                module = show_output.splitlines()[1].strip().split()[0]
                show_output = connection.send_command('sh module sfr details').strip()
                ips_type = 'SFR'
                
                for line in show_output.splitlines():
                    if 'Software version:' in line:                
                        version = line.split()[-1]
                    elif line.startswith('Status:'):
                        ips_status =  line.split()[-1]
                    elif 'Mgmt IP addr:' in line:            
                        ip_address =  line.split()[-1]
                    elif 'DC addr:' in line:                
                        manager =  line.split()[-1]          
                        if manager == 'Configured': 
                            manager = 'No DC Configured' 
                    elif 'Serial Number:' in line:
                        serial = line.split()[-1]
                ips_dict = {
                        'type':ips_type,
                        'serial':serial,
                        'version': version,
                        'status': ips_status,
                        'ip_address': ip_address,
                        'manager': manager,
                        }
            elif ' IPS ' in show_output:
                module = show_output.strip().split()[0]
                show_output = connection.send_command('sh module | in IPS').strip()
                version = show_output.strip().split()[-1]
                ips_type = 'IPS'
                ips_dict = {
                        'type': ips_type,
                        'version': version,
                        }
            else:
                show_output = connection.send_command('sh module | in ips').strip()
                if ' ips ' in show_output.lower():
                    try:
                        version = show_output.splitlines()[1].strip().split()[-1]
                        module = show_output.splitlines()[1].strip().split()[0]
                        ips_type = 'IPS'
                        ips_dict = {
                                'type': ips_type,
                                'version': version,
                                }
                    except IndexError:
                        version = show_output.splitlines()[0].strip().split()[-1]
                        module = show_output.splitlines()[0].strip().split()[0]
                        ips_type = 'IPS'
                        ips_dict = {
                                'type': ips_type,
                                'version': version,
                                }

            # Connect to IPS Module
            if ips_dict['type'] == 'IPS':
                try:
                    output = connection.send_command_timing(' session '+ module).strip().lower()
                    if output.endswith('login:'):
                        output = connection.send_command_timing(ips_username).strip().lower()
                        output = connection.send_command_timing(ips_password).strip().lower()
                        if output.endswith('login:'):
                            output = connection.send_command_timing(username).strip().lower()
                            output = connection.send_command_timing(password).strip().lower()
                            if output.endswith('login:'):
                                connection.send_command_timing('\n\n\n\n') 
                                connection.send_command_timing('\n\n\n\n') 
                                connection.send_command_timing('\n\n\n\n') 
                                connection.send_command_timing('\n\n\n\n') 
                                ips_dict.update({'connection':'failed'})
                            else:
                                ips_dict.update({'connection':'successful'})
                        else:
                            ips_dict.update({'connection':'successful'})
                    else:
                        ips_dict.update({'connection':'failed'})
                    if ips_dict['connection'] == 'successful':
                        show_output = connection.send_command_timing('show configuration | in host-ip|host-name').strip()
                        for line in show_output.splitlines():
                            if 'host-name' in line:
                                ips_dict.update({'hostname':line.split()[-1]})
                            if 'host-ip' in line:
                                ips_dict.update({'ip_address':line.split()[-1].split('/')[0]})
                        connection.send_command_timing('terminal length 100').strip().lower()
                        show_output = connection.send_command_timing('show version').strip()
                        for line in show_output.splitlines():
                            if 'serial' in line.lower():
                                ips_dict.update({'serial':line.split()[-1]})
                            elif 'signatures' in line.lower():
                                ips_dict.update({'signatures':line.split()[-2]})
                        connection.send_command_timing('exit')
                        connection.send_command_timing('\n')
                        connection.send_command_timing('\n')
                except:
                    ips_dict.update({'connection':'failed'})
            # Connect to SFR Module
            elif ips_dict['type'] == 'SFR':
                try:
                    output = connection.send_command_timing(' session '+ module).strip().lower()
                    if output.endswith('login:'):
                        output = connection.send_command_timing(ips_username).strip().lower()
                        output = connection.send_command_timing(ips_password).strip().lower()
                        if output.endswith('login:'):
                            output = connection.send_command_timing(sfr_username).strip().lower()
                            output = connection.send_command_timing(sfr_password).strip().lower()
                            if output.endswith('login:'):
                                output = connection.send_command_timing(username).strip().lower()
                                output = connection.send_command_timing(password).strip().lower()
                                if output.endswith('login:'):
                                    connection.send_command_timing('\n\n\n\n') 
                                    connection.send_command_timing('\n\n\n\n') 
                                    connection.send_command_timing('\n\n\n\n') 
                                    connection.send_command_timing('\n\n\n\n') 
                                    ips_dict.update({'connection':'failed'})
                                else:
                                    ips_dict.update({'connection':'successful'})
                            else:
                                ips_dict.update({'connection':'successful'})
                        else:
                            ips_dict.update({'connection':'successful'})
                    else:
                        ips_dict.update({'connection':'failed'})
                    if ips_dict['connection'] == 'successful':
                        show_output = connection.send_command_timing('show summary').strip()
                        show_output += connection.send_command_timing(' ') 
                        show_output += connection.send_command_timing(' ') 
                        show_output += connection.send_command_timing(' ') 
                        show_output += connection.send_command_timing(' ') 
                        for line in show_output.splitlines():
                            if 'rules' in line.lower():
                                vrt = line.split()[-1]
                                ips_dict.update({'vrt':vrt})
                            elif 'vdb' in line.lower():
                                ips_dict.update({'vdb':line.split()[-1]})
                        show_output = connection.send_command_timing('show hostname').strip()
                        for line in show_output.splitlines():
                            if 'hostname' in line.lower():
                                ips_dict.update({'hostname':line.split()[-1]})
                        show_output = connection.send_command_timing('show managers').strip()
                        for line in show_output.splitlines():
                            if 'registration' in line.lower():
                                ips_dict.update({'manager_status':line.split()[-1]})
                        connection.send_command_timing('exit')
                        connection.send_command_timing('\n')
                        connection.send_command_timing('\n')
                except:
                    ips_dict.update({'connection':'failed'})
            
            # Append IPS Dict to ASA Dict and send to output Queue
            asa_dict.update({'ips_details':ips_dict})
            #outputList.put(asa_dict)
            #print(json.dumps(asa_dict,indent=4))
            # Creating post data with ASA Dict 
            post_data = asa_dict 
            MONGO_POST(post_data,device,outputList,counter,date)
            jsonList.put(post_data)
            csvList.put(f'{hostname},{IP_address},{status},{asa_model},{failover_status},{asa_version},{asa_serial},{manager},{ips_type},{version},{vrt}\n')
            



            connection.disconnect()
    
        except NetMikoTimeoutException:
            outputList.put((f'\n!\n[{str(counter)}] CONNECTIVITY: CONNECTION TIMEOUT ERROR - {device}\n!\n'))
            post_data = {
                    'date': date,
                    'status': 'Failed',
                    'ip_address': IP_address,
                    'hostname': hostname,
                    'error': traceback.format_exc(),
                    }
            MONGO_POST(post_data,device,outputList,counter,date)
            jsonList.put(post_data)
            csvList.put(f'{hostname},{IP_address},Failed,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE\n')
                
    
        except :
            outputList.put(f'\n!\n[{str(counter)}] CONNECTIVITY: CONNECTION ERROR - {device}\n!\n')
            print(traceback.format_exc())
            post_data = {
                    'date': date,
                    'status': 'Failed',
                    'ip_address': IP_address,
                    'hostname': hostname,
                    'error': traceback.format_exc(),
                    }
            MONGO_POST(post_data,device,outputList,counter,date)
            jsonList.put(post_data)
            csvList.put(f'{hostname},{IP_address},Failed,NONE,NONE,NONE,NONE,NONE,NONE,NONE,NONE\n')

    outputList.put(None)
    csvList.put(None)
    jsonList.put(None)
    return

def script(form,configSettings):

    # Pull variables from web form
    devices = form['devices'].strip().splitlines()
    username = form['username']
    password = form['password']
    sfr_username = form['sfr_username']
    sfr_password = form['sfr_password']
    ips_username = form['ips_username']
    ips_password = form['ips_password']
    email = form['email']

    # Set Date variable
    date = datetime.today().ctime()

    # Netmiko Device Type
    device_type = 'cisco_asa'


    # Define Threading Queues
    NUM_THREADS = 200
    deviceList = queue.Queue()
    outputList = queue.Queue()
    jsonList = queue.Queue()
    csvList = queue.Queue()
    csvList.put('hostname,ip_address,status,model,failover_status,asa_version,asa_serial,ips_manager,ips_type,ips_version,ips_vrt\n')

    if len(devices) < NUM_THREADS:
        NUM_THREADS = len(devices)
    for line in devices:
        deviceList.put(line.strip())


    counter = 0

    # loop for devices 
    for i in range(NUM_THREADS):
        Thread(target=COMMANDS, args=(username,password,sfr_username,sfr_password,ips_username,ips_password,counter,device_type,devices,deviceList,outputList,date,csvList,jsonList)).start()
        time.sleep(1)



    # Random Generated Output File
    outputDirectory = ''
    outputFileName = ''
    for i in range(6):
        outputDirectory += chr(random.randint(97,122))
    outputDirectory += '/'
    if not os.path.exists(outputDirectory):
        os.makedirs(outputDirectory)
    for i in range(6):
        outputFileName += chr(random.randint(97,122))
    outputFileName += '.txt'
    #
    with open(outputFileName,'w') as outputFile:
        numDone = 0
        while numDone < NUM_THREADS:
            result = outputList.get()
            if result is None:
                numDone += 1
            else:
                outputFile.write(result)
    #
    csvFileName = ''
    for i in range(6):
        csvFileName += chr(random.randint(97,122))
    csvFileName += '.txt'
    #
    with open(csvFileName,'w') as csvFile:
        numDone = 0
        while numDone < NUM_THREADS:
            result = csvList.get()
            if result is None:
                numDone += 1
            else:
                csvFile.write(result)
    
    # Random Generated JSON Output File
    outputFileName_json = ''
    for i in range(6):
        outputFileName_json += chr(random.randint(97,122))
    outputFileName_json += '.txt'
    jsonOutput = []
    with open(outputFileName_json,'w') as jsonFile:
        numDone = 0
        while numDone < NUM_THREADS:
            result = jsonList.get()
            if result is None:
                numDone += 1
            else:
                jsonOutput.append(result)
        jsonFile.write(json.dumps(jsonOutput,indent=4))


    # ZIP Directory of Output Files
    find = outputDirectory.rfind('/')
    ZipFileName = outputDirectory[:find] + '.zip'
    with ZipFile(ZipFileName, 'w', ZIP_DEFLATED) as zf:
        # Writes Output File file and renames file
        zf.write(outputFileName, 'results.csv')
        zf.write(csvFileName, 'inventory.csv')
        zf.write(outputFileName_json,'inventory.json')
# =============================================================================
#         # Iterates through Directory
#         for File in os.scandir(outputDirectory):
#             if not File.name.startswith('.') and File.is_file():
#                 # Writes the file using the full file path + name
#                 zf.write(File.path, File.name)
# =============================================================================




    ##############################
    # Email Out Result
    #
    subject = 'Results of Firewall Inventory DataBase'
    html = """
    <html>
    <body>
    <h1>Output from Firewall Inventory DataBase</h1>
    </body>
    </html>
    """
    attachmentfile = ZipFileName
    attachmentname = 'results.zip'
    #
    From = 'ASA Discovery <ASA_Discovery@domain.com>'
    #
    emailHTMLWithRenamedAttachment(email,subject,html,attachmentfile,attachmentname,From)
    
    if os.path.exists(outputDirectory):
        shutil.rmtree(outputDirectory,ignore_errors=True)
    os.remove(ZipFileName)
    os.remove(outputFileName)
    os.remove(csvFileName)
    os.remove(outputFileName_json)

    return
