#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import json
import os.path
import random
import sqlite3
import time

import requests
from urllib.parse import unquote

def get_all_points():
    all_points_labels = []

    r = requests.post("http://82.166.165.1:5000/api?action=devices_list&username=GVK&password=gvk123")
    my_json  = r.content
    data = json.loads(my_json)
    
    for device in data['devices']:
        name_of_device = unquote(device['name'])
        print("Getting points of device " + str(name_of_device) + " with id: " + str(device['id']))

        try:
            r = requests.post("http://82.166.165.1:5000/api?action=points_list&username=GVK&password=gvk123&values=yes&device=" + str(device['id']))
        except:
            print("Connection refused. Waiting 5 seconds.")
            time.sleep(5)

        my_json  = r.content
        data = json.loads(my_json)
        # Get all points
        for point in data['points']:
            label = point['label']
            label = label.lower()
            label = label.replace(" ", "_")
            label = label.replace("-", "_")
            label = label.replace("on", "onn")
            label = label.replace("neutral_zonne", "neutral_zone")
            label = label.replace("onn/off_out", "onn_off_out")
            if "editable" in point:
                rw = "_W"
            else:
                rw = "_R"
            
            label = label + rw
            if label not in all_points_labels:
                all_points_labels.append(label)

    print(sorted(all_points_labels))
    print("We got all points.")

    return sorted(all_points_labels)

def create_devices_table():
    conn = sqlite3.connect('swissport_table.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY,timestamp TEXT, device_id TEXT, name TEXT, address TEXT, model TEXT, alarm TEXT)')

    # Get "Wildcard" columes
    all_points_labels = get_all_points()
    for label in all_points_labels:
        label = label.lower()
        label = label.replace(" ", "_")
        label = label.replace("-", "_")

        c.execute("ALTER TABLE devices ADD COLUMN '%s' 'INT'" % label)

    print(all_points_labels)
    print ("Finished")

dict_of_alarms = {}
def check_temps(all_points_labels):    
    print("THE BEGINNING")

    # Get Alarms
    
    try:
        r = requests.post("http://82.166.165.1:5000/api?action=alarms_data&username=GVK&password=gvk123")
    except:
        print("Connection refused. Waiting 5 seconds.")
        time.sleep(5)

    my_json  = r.content
    data = json.loads(my_json)

    for alarm in data["data"]:
        print("There is a " + alarm['alarm'] + " in device " + str(alarm['device']))
        dict_of_alarms.update({alarm['device'] : alarm['alarm']})

    print(dict_of_alarms)

    # Checking devices

    r = requests.post("http://82.166.165.1:5000/api?action=devices_list&username=GVK&password=gvk123")
    my_json  = r.content
    data = json.loads(my_json)
    
    number_of_devices = 0
    for device in data['devices']:
        number_of_devices = number_of_devices + 1
        name_of_device = unquote(device['name'])
        print("Checking device " + str(name_of_device) + " with id: " + str(device['id']))

        try:
            r = requests.post("http://82.166.165.1:5000/api?action=points_list&username=GVK&password=gvk123&values=yes&device=" + str(device['id']))
        except:
            print("Connection refused. Waiting 5 seconds.")
            time.sleep(5)

        my_json  = r.content
        data = json.loads(my_json)
        
        # Get all points of specific device
        all_specific_points = {}
        for point in data['points']:
            label = point['label'].lower()
            label = label.replace(" ", "_")
            label = label.replace("-", "_")
            label = label.replace("on", "onn")
            label = label.replace("neutral_zonne", "neutral_zone")
            label = label.replace("onn/off_out", "onn_off_out")
            if "editable" in point:
                rw = "_W"
            else:
                rw = "_R"
            
            label = label + rw

            all_specific_points.update({label : str(point['value'])})

        all_keys = ""
        for key in all_specific_points.keys():
            key = key.lower()
            key = key.replace(" ", "_")
            key = key.replace("-", "_")
            key = key.replace("on", "onn")
            key = key.replace("neutral_zonne", "neutral_zone")
            key = key.replace("onn/off_out", "onn_off_out")
            all_keys = all_keys + key + ", "
        
        all_keys = all_keys[:-2]

        # Customized Insertation
        unix = time.time()
        date = str(datetime.datetime.fromtimestamp(unix).strftime('%d-%m-%Y %H:%M'))

        # Check if the device has an alarm in dict_of_alarms
        alarm = "0"

        if device['id'] in dict_of_alarms.keys():
            alarm = dict_of_alarms.get(device['id'])

        print(alarm)
        shared_dict = {"timestamp": date, "device_id": device['id'], "name": name_of_device, "address": device['address'], "model": device['model'], "alarm": alarm}
        merged_dict = {**shared_dict, **all_specific_points}
        
        conn = sqlite3.connect('swissport_table.db')
        c = conn.cursor()
        columns = ', '.join(merged_dict.keys())
        placeholders = ':'+', :'.join(merged_dict.keys())
        query = 'INSERT INTO devices (%s) VALUES (%s)' % (columns, placeholders)
        print (query)
        c.execute(query, merged_dict)
        conn.commit()

        print("New query inserted")
    print ("number of devices: " + str(number_of_devices))
    conn = sqlite3.connect('customers.db')
    c = conn.cursor()
    customer_name = "Swissport"
    q = '''UPDATE customers SET number_of_devices = ''' + str(number_of_devices) + ''' WHERE name = \'''' + str(customer_name) + "\'"
    print(q)
    c.execute(q)
    conn.commit()

    print("THE END")
    c.close()
    conn.close()

# Get all points once

all_specific_points = get_all_points()

print (os.path.isfile("swissport_table.db"))
if os.path.isfile("swissport_table.db") == False:
    create_devices_table()

conn = sqlite3.connect('swissport_table.db')
c = conn.cursor()

# Get all points once
while True:
    check_temps(all_specific_points)