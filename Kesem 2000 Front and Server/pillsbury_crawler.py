#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import json
import random
import sqlite3
import time
from xml.etree import ElementTree
import os.path
import re
import requests

def get_all_points():
    all_points_labels = []
    all_cids = []
    all_vids = []
    all_rw = []
    url="http://84.228.13.207:1234/html/xml.cgi?"
    body = """xml=<cmd action="read_devices"/>"""

    response = requests.post(url,data=body)

    nice_response = response.content
    tree = ElementTree.fromstring(nice_response)

    devices = tree.findall('device')

    # Getting all the names of the devices

    for device in devices:
        name = device.find('name').text
        print(name)
        nodetype = device.attrib['nodetype']
        if nodetype == "16":
            device_id = device.find('device_id').text
            node = device.attrib['node']
            alarm = device.attrib['alarm']
            online = device.attrib['online']
        else:
            device_id = ""
            node = ""
            alarm = ""
            online = ""

        # Getting all points of the device
        
        url="http://84.228.13.207:1234/html/xml.cgi?"
        body= """xml=<cmd action="read_parm_info" device_id= \"""" + device_id + """\"/>"""

        response = requests.post(url,data=body)

        nice_response = response.content
        all_parms = re.findall(r'<parm(.*?)</parm>', str(nice_response))
        # Search for points

        for parm in all_parms:
#            print(parm)
            point = re.search(r'name=\"(.*?)\"', str(parm))
            point = point[1]

            cid = re.search(r'cid=\"(.*?)\"', str(parm))
            cid = cid[1]

            vid = re.search(r'vid=\"(.*?)\"', str(parm))
            vid = vid[1]

            rw = re.search(r'rw=\"(.*?)\"', str(parm))
            rw = rw[1]

            point = point.lower()
            point = point + "_CID_" + cid + "_VID_" + vid + "_" + rw
            point = point.replace("/", "")
            point = point.replace(" ", "_")
            point = point.replace("-", "")
            point = point.replace("+", "")
            point = point.replace(":", "")
            point = point.replace("%", "percent")
            point = point.replace(".", "")
            point = point.replace("=", "")

            point = "_" + point

            if point not in all_points_labels:
                all_points_labels.append(point)
    
    print(sorted(all_points_labels))
    return (sorted(all_points_labels))


def create_devices_table():
    conn = sqlite3.connect('pillsbury_table.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, timestamp TEXT, device_id TEXT, name TEXT, nodetype TEXT, node TEXT, alarm TEXT, online TEXT)')

    # Get "Wildcard" columes
    all_points_labels = get_all_points()
    for label in all_points_labels:
        c.execute("ALTER TABLE devices ADD COLUMN '%s' 'INT'" % label)

    print ("Finished")

def check_temps():    
    print("THE BEGINNING")
    all_points = []
    all_specific_points = {}
    this_round_alarms = {}
    url="http://84.228.13.207:1234/html/xml.cgi?"
    body = """xml=<cmd action="read_devices"/>"""

    response = requests.post(url,data=body)

    nice_response = response.content
    tree = ElementTree.fromstring(nice_response)

    devices = tree.findall('device')
    print("number of devices: ")
    number_of_devices = len(devices)
    print(number_of_devices)
    conn = sqlite3.connect('customers.db')
    c = conn.cursor()
    customer_name = "Pillsbury"
    q = '''UPDATE customers SET number_of_devices = ''' + str(number_of_devices) + ''' WHERE name = \'''' + str(customer_name) + "\'"
    print(q)
    c.execute(q)
    conn.commit()

    for device in devices:
        name = device.find('name').text
        print(name)
        nodetype = device.attrib['nodetype']
        if nodetype == "16":
            device_id = device.find('device_id').text
            node = device.attrib['node']
            alarm = device.attrib['alarm']
            online = device.attrib['online']

            if alarm == "1":
                url="http://84.228.13.207:1234/html/xml.cgi?"
                body = 'xml=<cmd action="read_device_alarms" nodetype="16" node=\"' + node + '\" mod="0" point="0"/>'

                response = requests.post(url,data=body)
                nice_response = response.content
                tree = ElementTree.fromstring(nice_response)
                alarm = tree.find('active/ref').attrib['name']
                print("name: " + name + " alarm: " + alarm)
        
                this_round_alarms.update({name : alarm})
                print(this_round_alarms)
            nice_response = response.content
            tree = ElementTree.fromstring(nice_response)

            url="http://84.228.13.207:1234/html/xml.cgi?"
            body= """xml=<cmd action="read_parm_info" device_id= \"""" + device_id + """\"/>"""

            response = requests.post(url,data=body)

            nice_response = response.content
            all_parms = re.findall(r'<parm(.*?)</parm>', str(nice_response))
            # Search for specific points

            body = """xml=<cmd action="read_val">"""
            for parm in all_parms:
                time.sleep(0.1)
                point = re.search(r'name=\"(.*?)\"', str(parm))
                point = point[1]

                cid = re.search(r'cid=\"(.*?)\"', str(parm))
                cid = cid[1]

                vid = re.search(r'vid=\"(.*?)\"', str(parm))
                vid = vid[1]

                rw = re.search(r'rw=\"(.*?)\"', str(parm))
                rw = rw[1]

                point = point.lower()
                point = point + "_CID_" + cid + "_VID_" + vid + "_" + rw
                point = point.replace("/", "")
                point = point.replace(" ", "_")
                point = point.replace("-", "")
                point = point.replace("+", "")
                point = point.replace(":", "")
                point = point.replace("%", "percent")
                point = point.replace(".", "")
                point = point.replace("=", "")
                point = "_" + point
                if point not in all_points:
                    all_points.append(point)
                    body = body +  """<val nodetype="16" node= \"""" + node + """\"cid=\"""" + cid + """\"vid=\"""" + vid + """\" />"""
                    

            url="http://84.228.13.207:1234/html/xml.cgi?"
            body = body +  """</cmd>"""

            response = requests.post(url,data=body)
            nice_response = response.content
            tree = ElementTree.fromstring(nice_response)
            values = tree.findall('val')
            i = -1

            print(nice_response)

            for value in values:
                i = i + 1
                print("Point: " + all_points[i] + " with value: " + value.get("parval"))
                all_specific_points.update({all_points[i] : value.get("parval")})

            unix = time.time()
            date = str(datetime.datetime.fromtimestamp(unix).strftime('%d-%m-%Y %H:%M'))
            shared_dict = {"timestamp": date, "device_id": device_id, "name": name, "nodetype": nodetype, "node": node, "alarm": alarm, "online": online}
            merged_dict = {**shared_dict, **all_specific_points}
        
            conn = sqlite3.connect('pillsbury_table.db')
            c = conn.cursor()
            columns = ', '.join(merged_dict.keys())
            placeholders = ':'+', :'.join(merged_dict.keys())
            query = 'INSERT INTO devices (%s) VALUES (%s)' % (columns, placeholders)
            c.execute(query, merged_dict)
            conn.commit()
            print("New query inserted")

    print("THE END")
    c.close()
    conn.close()


print (os.path.isfile("pillsbury_table.db"))
if os.path.isfile("pillsbury_table.db") == False:
    create_devices_table()

conn = sqlite3.connect('pillsbury_table.db')
c = conn.cursor()

# Get all points once
while True:
    check_temps()
