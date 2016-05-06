#!/usr/bin/python
#   File : check_beacon_presence.py
#   Author: jmleglise
#   Date: 06-May-2016
#   Info: Beacon (BlueTooth Low Energy V4.0) detection and reports back to domoticz
#   URL : https://github.com/jmleglise/mylittle-domoticz/edit/master/Presence%20detection%20%28beacon%29/check_beacon_presence.py
#   Version : 1.0
#
# Feature : 
# Check the presence of a list of beacon and update uservariables in Domoticz accordingly. 
# When the MACADRESS of the beacons are detected, send "HOME". And send "AWAY" when the beacons are not in range.
# The detection is very fast : around 4 secondes. And the absence is verified every 15 seconds by comparing the hour of the last presence.
#
# Ressources :
# https://wiki.tizen.org/wiki/Bluetooth
# https://github.com/adamf/BLE/blob/master/ble-scanner.py
#
# Required in Domoticz : An uservariable of type String for each BLE Tag

# Change your IP and Port here :
URL_DOMOTICZ = 'http://192.168.0.20:8080/json.htm?type=command&param=updateuservariable&idx=PARAM_IDX&vname=PARAM_NAME&vtype=2&vvalue=PARAM_CMD'
# Configure your Beacon here : name (same as the uservariable in Domoticz), MAC ADDR, TimeOut in sec, 0 , idx of uservariable Domoticz
# Timeout is the elapsed time  without a detetion for switching the beacon AWAY. Ie :if your beacon emits every 3 to 8 seondes, a timeout of 15 secondes seems good.
TAG_DATA = [  
			["Tag_white","XX:Xx:XX:xx:xx:xx",15,0,8],
			["Tag_Orange","xx:xx:78:38:xx:xx",15,0,6],
			["Tag_Green","xx:ff:60:00:xx:xx",15,0,7]
			]
################ Nothing to edit under this line #####################################################################################


import os
import sys
import struct
import bluetooth._bluetooth as bluez
import time
import requests
import signal
import threading


LE_META_EVENT = 0x3e
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_ENABLE=0x000C
EVT_LE_CONN_COMPLETE=0x01
EVT_LE_ADVERTISING_REPORT=0x02

def printpacket(pkt):
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])

def packed_bdaddr_to_string(bdaddr_packed):
    return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

def hci_disable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x00)

def hci_toggle_le_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)

def handler(signum = None, frame = None):
    time.sleep(1)  #here check if process is done
    sys.exit(0)   
    
for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
    signal.signal(sig, handler)

def RequestThread(idx,cmd, name):
    try:
        url = URL_DOMOTICZ
        url=url.replace('PARAM_IDX',str(idx))
        url=url.replace('PARAM_CMD',str(cmd))
        url=url.replace('PARAM_NAME',str(name))
        result = requests.get(url)
        print url
        #  logging.debug(" %s -> %s" % (threading.current_thread(), result))
    except requests.ConnectionError, e:
        print "Request Failed", url
        #  logging.warning(' %s CONNECTION ERROR %s' % (threading.current_thread(), e) )

class CheckAbsenceThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
            time_check_absence = time.time()
            while True:
                if time.time()>time_check_absence+15 : # check every 15 sec
                    time_check_absence=time.time()
                    for tag in TAG_DATA:
                        if time.time()>tag[3]+tag[2] and time.time()<tag[3]+2*tag[2]:  #lastseen + timeout
                            #print time.ctime()," ",tag[0]," send away cmd"
                            threadReqAway = threading.Thread(target=RequestThread,args=(tag[4],"AWAY",tag[0]))
                            threadReqAway.start()

dev_id = 0
try:
    sock = bluez.hci_open_dev(dev_id)

except:
    print "Error accessing bluetooth dongle..."
    sys.exit(1)

old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
hci_toggle_le_scan(sock, 0x01)

th=CheckAbsenceThread()
th.daemon=True
th.start()

while True:
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
    
    pkt = sock.recv(255)
    ptype, event, plen = struct.unpack("BBB", pkt[:3])

    if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            i =0
    elif event == bluez.EVT_NUM_COMP_PKTS:
            i =0 
    elif event == bluez.EVT_DISCONN_COMPLETE:
            i =0 
    elif event == LE_META_EVENT:
            subevent, = struct.unpack("B", pkt[3])
            pkt = pkt[4:]
            if subevent == EVT_LE_CONN_COMPLETE:
                le_handle_connection_complete(pkt)
            elif subevent == EVT_LE_ADVERTISING_REPORT:
                num_reports = struct.unpack("B", pkt[0])[0]
                report_pkt_offset = 0
                for i in range(0, num_reports):
                            #print time.ctime()
                            #print "\tUDID: ", printpacket(pkt[report_pkt_offset -22: report_pkt_offset - 6])
                            #print "\tMAJOR: ", printpacket(pkt[report_pkt_offset -6: report_pkt_offset - 4])
                            #print "\tMINOR: ", printpacket(pkt[report_pkt_offset -4: report_pkt_offset - 2])
                            #print "\tMAC address: ", packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                            #print "\t(Unknown):", struct.unpack("b", pkt[report_pkt_offset -2]) # don't know what this byte is.  It's NOT TXPower
                            #print "\tRSSI:", struct.unpack("b", pkt[report_pkt_offset -1]) #  Signal strenght !
                            for tag in TAG_DATA:
                                if packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9]) == tag[1]:  # MAC ADDRESS
                                    #print time.time(),"  ",tag[0]
                                    elapsed_time=int(time.time()-tag[3])  # lastseen
                                    if elapsed_time>tag[2]: # timeout
                                        threadReqHome = threading.Thread(target=RequestThread,args=(tag[4],"HOME",tag[0]))
                                        threadReqHome.start()
                                        #print "send detection",tag[0]
                                    tag[3]=time.time()   # update lastseen
                                    
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
