#!/usr/bin/python
import socket
import sys
import select

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if sys.argv[1] == "-c":
	s.connect((sys.argv[2],9999))
	
	input = [s,sys.stdin]
	while 1:

	        iready, oready, eready = select.select(input,[],[])

        	for i in iready:
                	if i == s:
                        	data = i.recv(256)
                        	if not data: break
				if data == '':
					s.close()
					sys.exit()
                        	print data,
                	elif i == sys.stdin:
                        	message = sys.stdin.readline()
                        	if message == '':
                                	s.close
					sys.exit();
                        	else:
                                	s.send(message)

elif sys.argv[1] == "-s":
	s.bind(('', 9999))
	s.listen(1)
	conn, addr = s.accept()

	input = [conn,sys.stdin]
	while 1:

		iready, oready, eready = select.select(input,[],[])
	
		for i in iready:
			if i == conn:
				data = i.recv(256)
				if not data: break
				if data == '':
					s.close()
					sys.exit()
				print data,
			elif i == sys.stdin:
				message = sys.stdin.readline()
				if message == '':
					conn.close
					sys.exit();
				else:
					conn.send(message)

