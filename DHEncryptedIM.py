#!/usr/bin/python

#Author : Henry Tan
#For COSC235
#Solution for HW1 - Part 1

import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import random

from collections import deque
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto.Random import random

from collections import deque

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
confkey = 0;
logger = logging.getLogger('main')
###########

#checks to see if command line arguments are written correctly
def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.')
  parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to')
  parser.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int, 
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')

  return parser.parse_args()
#message that prints if program is run with incorrect command line arguments
def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"

def sigint_handler(signal, frame):
  logger.debug("SIGINT Captured! Killing")
  global s, server_s
  if s is not None:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
  if server_s is not None:
    s.close()

  quit()
  
#init for program, connects to client/server and runs Diffie-Hellman
def init(crypt):
  global s
  global confkey
  args = parse_arguments()

  logging.basicConfig()
  logger.setLevel(logging.CRITICAL)
  
  #Catch the kill signal to close the socket gracefully
  signal.signal(signal.SIGINT, sigint_handler)

  if args.connect is None and args.server is False:
    print_how_to()
    quit()

  if args.connect is not None and args.server is not False:
    print_how_to()
    quit() 



  #hash key and take first 128 bits (=16 bytes)


  if args.connect is not None: #this is the client
    iv=os.urandom(32)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
    s.connect((args.connect, args.port))
    s.send(iv)
    a = random.randint(1,9999999)
    g = 2
    p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
    A = pow(g,a,p)
    s.send(str(A))
    B = long(s.recv(1024))
    confkey = pow(B,a,p)
    confkey=SHA256.new(str(confkey)).digest()[0:16]
    crypt['confout']=AES.new(confkey, AES.MODE_CBC, iv[:16])
    crypt['confin']=AES.new(confkey, AES.MODE_CBC, iv[16:])

  if args.server is not False: #this is the server
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port))
    server_s.listen(1) #Only one connection at a time
    s, remote_addr = server_s.accept()
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))
    iv=s.recv(32)
    b = random.randint(10485,16777)
    g = 2
    p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
    A = long(s.recv(1024))
    B = pow(g,b,p)
    s.send(str(B))
    confkey = pow(A,b,p)
    confkey=SHA256.new(str(confkey)).digest()[0:16]
    crypt['confout']=AES.new(confkey, AES.MODE_CBC, iv[16:])
    crypt['confin']=AES.new(confkey, AES.MODE_CBC, iv[:16])
def numto16bytestr(num):
  #converts int to 16-byte string with a bunch of 0s in front of it
  #obviously 16 bytes is unnecessarily large, but: simplicity.
  num = str(num)
  return (16-len(num))*'0' + num

def padstrto16bytes(data):
  #ensures string ends in newline, and pads to next multiple of 16 bytes
  #if str[-1] is not '\n':
  #  str += '\n'
  return data + (-len(data)%16)*'x'

def encodemessage(data,crypt):
  data = numto16bytestr(len(data))+padstrto16bytes(data)
  data = crypt['confout'].encrypt(data)
  return data

def decodemessage(data,crypt):
  data = crypt['confin'].decrypt(data)
  data = data[16:16+int(data[:16])]
  return data
#main method, does the actual encoding, sending, receiving, and decoding of messages
def main():
  global confkey
  global s
  datalen=1024
  
  crypt={}
  #crypt=['authout':None,'confout':None,'authin':None,'confin':None]

  init(crypt)
  
  inputs = [sys.stdin, s]
  outputs = [s]

  output_buffer = deque()

  while s is not None: 
    #Prevents select from returning the writeable socket when there's nothing to write
    if (len(output_buffer) > 0):
      outputs = [s]
    else:
      outputs = []

    readable, writeable, exceptional = select.select(inputs, outputs, inputs)

    if s in readable:
      data = s.recv(datalen)
      #print "received packet, length "+str(len(data))

      if ((data is not None) and (len(data) > 0)):
        data = decodemessage(data, crypt)
        sys.stdout.write(data) #Assuming that stdout is always writeable
      else:
        #Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable:
      data = sys.stdin.readline(16384)
      if(len(data) > 0):
        for datapiece in [data[i:i+datalen-48] for i in range(0,len(data),datalen-48)]:
          datapiece = encodemessage(datapiece, crypt)
          output_buffer.append(datapiece)
      else:
        #EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable:
      if (len(output_buffer) > 0):
        data = output_buffer.popleft()
        bytesSent = s.send(data)
        #If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:])

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None

###########

if __name__ == "__main__":
  main()
