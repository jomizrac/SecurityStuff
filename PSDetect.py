#!/usr/bin/python


import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import time
from scapy.all import *
sniffed = {'0':[0,0]}
startTime = 0
#find own IP so you aren't worried about outgoing connections
def getMyIP():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("8.8.8.8", 80))
  return s.getsockname()[0]

#looks through all attempted connections to the computer
def ip_callback(packet):
  global startTime
  global sniffed
  if IP in packet:
    source_ip = packet[IP].src
    dest_ip = packet[IP].dst
    dest_port = packet.dport
    if sniffed.has_key(source_ip):
      if sniffed.get(source_ip)[0] == dest_port - 1:
        sniffed[source_ip] = [dest_port,sniffed[source_ip][1]+1]
      else:
         sniffed[source_ip] = [dest_port,1]
    else:
      sniffed[source_ip] = [dest_port,1]
    if (time.time()-startTime >=5):
      for key, value in sniffed.items():
        if value[1] >= 15:
          print "Scanner Detected.  The scanner originated from host " + key
      sniffed.clear()
      startTime=time.time()


#runs sniff to continuously check on the attempted connections
startTime = time.time()
sniff(prn=ip_callback, filter="tcp and not src net " + getMyIP())
