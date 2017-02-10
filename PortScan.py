#!/usr/bin/python


import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import time


s = None


counter = 0
targetName = sys.argv[1]
startTime = time.time()
for i in range(0, 65536):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  current = s.connect_ex(( targetName, i))
  if current == 0:
    try:
      service = socket.getservbyport(i)
    except:
      service = "[Unassigned]"
    print str(i) + " " + service
    counter += 1
  s.close()
endTime = time.time()
timeElapsed = endTime-startTime
rate = 65535/timeElapsed
print str(timeElapsed) + " " + str(counter) + " " + str(rate)
