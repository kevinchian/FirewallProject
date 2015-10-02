#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = self.extractRules(config)
        self.geoList = self.loadGeoIP(config)
        self.ANY = 0
        self.SINGLE = 1
        self.PREFIXIP = 2
        self.COUNTRYCODE = 3
        self.RANGE = 4
        self.httpDict = {}   #key:value = (dest ip, source port):[requestHeader, responseHeader, requestSeq, responseSeq, gotRequestHeader, gotResponseHeader, log] => (#, #) : [string, string, #, #, boolean, boolean, boolean]
        self.wrap = False

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        try:
            send = True
            try:
                ip_byte_length, = struct.unpack('!B', pkt[0]) #IHL on IP Header
                ip_byte_length = (ip_byte_length & 0b00001111) * 4 #gets the offset to the tcp, udp, icmp headers
                if(ip_byte_length < 20): #Corrupt packet
                    return
                pkt_len, = struct.unpack('!H', pkt[2:4])
                if (pkt_len != len(pkt)) or (ip_byte_length > len(pkt)) : #packet length doesn't match the expected length
                    return
                protocol, = struct.unpack('!B', pkt[9]) #protocol on IP Header
                if protocol == 'udp':
                    udp_len, = struct.unpack('!H', pkt[ip_byte_length+4:ip_byte_length+6])
                    if udp_len + ip_byte_length != len(pkt):
                        return
                src_ip = pkt[12:16]
                dst_ip = pkt[16:20]
                ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
            except:
                return
            if pkt_dir == PKT_DIR_INCOMING:
                dir_str = 'incoming'
            else:
                dir_str = 'outgoing'

            if pkt_dir == PKT_DIR_INCOMING:
                try:
                    external_ip = socket.inet_ntoa(src_ip)
                except:
                    return
                if protocol == 6: #tcp
                    try:
                        external_port, = struct.unpack('!H', pkt[ip_byte_length:ip_byte_length+2])
                    except:
                        return
                    for rule in self.rules:
                        if rule[1].lower() == 'tcp': #check if rule is tcp
                            external_ip_type = self.ip_type(rule[2])
                            if external_ip_type == self.SINGLE:
                                if rule[2] != external_ip:
                                    continue
                            elif external_ip_type == self.PREFIXIP:
                                network_mask = rule[2].split('/')
                                offset = int(network_mask[1])
                                try:
                                    if (struct.unpack('!L', src_ip)[0]>>(32-offset)) != (struct.unpack('!L', socket.inet_aton(network_mask[0]))[0]>>(32-offset)):
                                        continue
                                except:
                                    return
                            elif external_ip_type == self.COUNTRYCODE:
                                if getCountryCode(external_ip, self.geoList) != rule[2]:
                                    continue
                            external_port_type = self.port_type(rule[3])
                            if external_port_type == self.SINGLE:
                                if int(rule[3]) != external_port:
                                    continue
                            elif external_port_type == self.RANGE:
                                if not inRange(rule[3], external_port):
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            break #reached end without continue, so we know this rule matches

                elif protocol == 1: #ICMP
                    try:
                        external_port, = struct.unpack('!B', pkt[ip_byte_length])
                    except:
                        return
                    for rule in self.rules:
                        if rule[1].lower() == 'icmp':
                            external_ip_type = self.ip_type(rule[2])
                            if external_ip_type == self.SINGLE:
                                if rule[2] != external_ip:
                                    continue
                            elif external_ip_type == self.PREFIXIP:
                                network_mask = rule[2].split('/')
                                offset = int(network_mask[1])
                                try:
                                    if (struct.unpack('!L', src_ip)[0]>>(32-offset)) != (struct.unpack('!L', socket.inet_aton(network_mask[0]))[0]>>(32-offset)):
                                        continue
                                except:
                                    return
                            elif external_ip_type == self.COUNTRYCODE:
                                if getCountryCode(external_ip, self.geoList) != rule[2]:
                                    continue
                            external_port_type = self.port_type(rule[3])
                            if external_port_type == self.SINGLE:
                                if external_port != int(rule[3]):
                                    continue
                            elif external_port_type == self.RANGE:
                                if not inRange(rule[3], external_port):
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            break #reached end without continue, so we know this rule matches
                
                elif protocol == 17: #UDP/DNS
                    try:
                        external_port, = struct.unpack('!H', pkt[ip_byte_length:ip_byte_length+2])
                    except:
                        return
                    domain = ""
                    dns = True
                    
                    if external_port == 53:
                        try:
                            qdcount, = struct.unpack('!H', pkt[ip_byte_length+12:ip_byte_length+14])
                        except:
                            return
                        if qdcount != 1:
                            dns = False
                        else:
                            label_len = 0
                            beginning = True #see if beginning of domain name or middle
                            qname_index = ip_byte_length+20
                            try:
                                while(struct.unpack('!B',pkt[qname_index])[0] != 0):
                                    if label_len == 0:
                                        label_len, = struct.unpack('!B',pkt[qname_index])
                                        if not beginning:
                                            domain = domain + "."
                                        beginning = False
                                    else:
                                        label_len-=1
                                        domain = domain + chr(struct.unpack('!B',pkt[qname_index])[0])
                                    qname_index+=1
                                qtype, = struct.unpack('!H', pkt[qname_index+1:qname_index+3])
                                qclass, = struct.unpack('!H', pkt[qname_index+3:qname_index+5])
                            except:
                                return
                            if qtype != 1:
                                if qtype != 28:
                                    dns = False
                            if qclass != 1:
                                dns = False
                    else:
                        dns = False
                    for rule in self.rules:
                        if rule[1].lower() == 'udp':
                            external_ip_type = self.ip_type(rule[2])
                            if external_ip_type == self.SINGLE:
                                if rule[2] != external_ip:
                                    continue
                            elif external_ip_type == self.PREFIXIP:
                                network_mask = rule[2].split('/')
                                offset = int(network_mask[1])
                                try:
                                    if (struct.unpack('!L', src_ip)[0]>>(32-offset)) != (struct.unpack('!L', socket.inet_aton(network_mask[0]))[0]>>(32-offset)):
                                        continue
                                except:
                                    return
                            elif external_ip_type == self.COUNTRYCODE:
                                if getCountryCode(external_ip, self.geoList) != rule[2]:
                                    continue
                            external_port_type = self.port_type(rule[3])
                            if external_port_type == self.SINGLE:
                                if external_port != int(rule[3]):
                                    continue
                            elif external_port_type == self.RANGE:
                                if not inRange(rule[3], external_port):
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            break #reached end without continue, so we know this rule matches

                        if (rule[1].lower() == 'dns') and dns:
                            domain = domain.lower()
                            if rule[2][0] == '*':
                                if not domain.endswith(rule[2].strip('*')):
                                    continue
                            else:
                                if domain != rule[2]:
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            break #reached end without continue, rule matches
            elif pkt_dir == PKT_DIR_OUTGOING:
                try:
                    external_ip = socket.inet_ntoa(dst_ip) 
                except:
                    return
                if protocol == 6: #tcp
                    try:
                        external_port, = struct.unpack('!H', pkt[ip_byte_length+2:ip_byte_length+4])
                    except:
                        return
                    for rule in self.rules:
                        if rule[1].lower() == 'tcp': #check if rule is tcp
                            external_ip_type = self.ip_type(rule[2])
                            if external_ip_type == self.SINGLE:
                                if rule[2] != external_ip:
                                    continue
                            elif external_ip_type == self.PREFIXIP:
                                network_mask = rule[2].split('/')
                                offset = int(network_mask[1])
                                try:
                                    if (struct.unpack('!L', dst_ip)[0]>>(32-offset)) != (struct.unpack('!L', socket.inet_aton(network_mask[0]))[0]>>(32-offset)):
                                        continue
                                except:
                                    return
                            elif external_ip_type == self.COUNTRYCODE:
                                if getCountryCode(external_ip, self.geoList) != rule[2]:
                                    continue
                            external_port_type = self.port_type(rule[3])
                            if external_port_type == self.SINGLE:
                                if int(rule[3]) != external_port:
                                    continue
                            elif external_port_type == self.RANGE:
                                if not inRange(rule[3], external_port):
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            if rule[0].lower() == 'deny':
                                rst_pkt = create_rst_packet(pkt)
                                self.iface_int.send_ip_packet(rst_pkt)
                                return
                            break #reached end without continue, so we know this rule matches

                elif protocol == 1: #ICMP
                    try:
                        external_port, = struct.unpack('!B', pkt[ip_byte_length])
                    except:
                        return
                    for rule in self.rules:
                        if rule[1].lower() == 'icmp':
                            external_ip_type = self.ip_type(rule[2])
                            if external_ip_type == self.SINGLE:
                                if rule[2] != external_ip:
                                    continue
                            elif external_ip_type == self.PREFIXIP:
                                network_mask = rule[2].split('/')
                                offset = int(network_mask[1])
                                try:
                                    if (struct.unpack('!L', dst_ip)[0]>>(32-offset)) != (struct.unpack('!L', socket.inet_aton(network_mask[0]))[0]>>(32-offset)):
                                        continue
                                except:
                                    return
                            elif external_ip_type == self.COUNTRYCODE:
                                if getCountryCode(external_ip, self.geoList) != rule[2]:
                                    continue
                            external_port_type = self.port_type(rule[3])
                            if external_port_type == self.SINGLE:
                                if external_port != int(rule[3]):
                                    continue
                            elif external_port_type == self.RANGE:
                                if not inRange(rule[3], external_port):
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            break #reached end without continue, so we know this rule matches
                elif protocol == 17: #UDP/DNS
                    try:
                        external_port, = struct.unpack('!H', pkt[ip_byte_length+2:ip_byte_length+4])
                    except:
                        return
                    domain = ""
                    dns = True
                    qtype_is_a = False
                    qname_begin = 0
                    qname_index = 0
                    if external_port == 53:
                        try:
                            qdcount, = struct.unpack('!H', pkt[ip_byte_length+12:ip_byte_length+14])
                        except:
                            return
                        if qdcount != 1:
                            dns = False
                        else:
                            label_len = 0
                            beginning = True #see if beginning of domain name or middle
                            qname_index = ip_byte_length+20
                            qname_begin = qname_index
                            try:
                                while(struct.unpack('!B',pkt[qname_index])[0] != 0):
                                    if label_len == 0:
                                        label_len, = struct.unpack('!B',pkt[qname_index])
                                        if not beginning:
                                            domain = domain + "."
                                        beginning = False
                                    else:
                                        label_len-=1
                                        domain = domain + chr(struct.unpack('!B',pkt[qname_index])[0])
                                    qname_index+=1
                                qtype, = struct.unpack('!H', pkt[qname_index+1:qname_index+3])
                                qclass, = struct.unpack('!H', pkt[qname_index+3:qname_index+5])
                            except:
                                return
                            if qtype != 1:
                                if qtype != 28:
                                    dns = False
                            if qtype == 1:
                                qtype_is_a = True
                            if qclass != 1:
                                dns = False
                    else:
                        dns = False
                    for rule in self.rules:
                        if rule[1].lower() == 'udp':
                            external_ip_type = self.ip_type(rule[2])
                            if external_ip_type == self.SINGLE:
                                if rule[2] != external_ip:
                                    continue
                            elif external_ip_type == self.PREFIXIP:
                                network_mask = rule[2].split('/')
                                offset = int(network_mask[1])
                                try:
                                    if (struct.unpack('!L', dst_ip)[0]>>(32-offset)) != (struct.unpack('!L', socket.inet_aton(network_mask[0]))[0]>>(32-offset)):
                                        continue
                                except:
                                    return
                            elif external_ip_type == self.COUNTRYCODE:
                                if getCountryCode(external_ip, self.geoList) != rule[2]:
                                    continue
                            external_port_type = self.port_type(rule[3])
                            if external_port_type == self.SINGLE:
                                if external_port != int(rule[3]):
                                    continue
                            elif external_port_type == self.RANGE:
                                if not inRange(rule[3], external_port):
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            break #reached end without continue, so we know this rule matches

                        if (rule[1].lower() == 'dns') and dns:
                            domain = domain.lower()
                            if rule[2][0] == '*':
                                if not domain.endswith(rule[2].strip('*')):
                                    continue
                            else:
                                if domain != rule[2]:
                                    continue
                            if rule[0].lower() == 'drop':
                                send = False
                            if rule[0].lower() == 'deny':
                                if qtype_is_a:
                                    dns_pkt = create_dns_packet(pkt, qname_begin, qname_index)
                                    self.iface_int.send_ip_packet(dns_pkt)
                                return
                            break #reached end without continue, rule matches
            ####proj3b code#####
            if (protocol == 6) and (external_port == 80) and (send == True) : #tcp, dest port == 8, send == True
                #try:
                lenIPHeader = (struct.unpack('!B', pkt[0])[0] & 0b00001111) * 4    #IP Header len in bytes
                lenTCPHeader = (struct.unpack('!B', pkt[lenIPHeader + 12])[0] >> 4) * 4     #TCP Header len in bytes
                totalData, = (struct.unpack('!H', pkt[2:4]))   #Total IP Datagram in bytes
                httpData = totalData - (lenIPHeader + lenTCPHeader) #size of http data in bytes
                flagsTCP, = struct.unpack('!B', pkt[lenIPHeader+13])
                if (pkt_dir == PKT_DIR_OUTGOING):   #request
                    ip = str(struct.unpack('!B', pkt[16])[0]) + '.' + str(struct.unpack('!B', pkt[17])[0]) + '.' + str(struct.unpack('!B', pkt[18])[0]) + '.' + str(struct.unpack('!B', pkt[19])[0])
                    TCPConnection = (ip, struct.unpack('!H', pkt[lenIPHeader:lenIPHeader+2])[0])
                    seq, = struct.unpack('!L', pkt[lenIPHeader+4:lenIPHeader+8]) #get current seq
                    if (not (TCPConnection in self.httpDict)) and (flagsTCP == 2):  #creating a new TCP connection for this http request
                        self.httpDict[TCPConnection] = ['', '', seq+1, 0, False, False, False]
                        self.wrap = False
                    elif (TCPConnection in self.httpDict) and not (httpData == 0):  #continuing packets
                        if ((seq > self.httpDict[TCPConnection][2]) or (self.wrap and (seq < self.httpDict[TCPConnection][2]))): #if seq is greater than what we expected (out of order packet)
                            send = False    #drop packet
                        elif ((seq < self.httpDict[TCPConnection][2]) or (self.wrap and (seq > self.httpDict[TCPConnection][2]))): #if seq is less (retransmitted packet)
                            a=1
                        else:   #seq is what we expected
                            if (self.httpDict[TCPConnection][4] and self.httpDict[TCPConnection][5]):    #if exist in dict and already got both request and response header, must be new request.
                                self.httpDict[TCPConnection] = ['', '', self.httpDict[TCPConnection][2], self.httpDict[TCPConnection][3], False, False, False]
                            tempSeq = seq+httpData % 4,294,967,295
                            if (tempSeq < self.httpDict[TCPConnection][2]):
                                self.wrap = True
                            else:
                                self.wrap = False
                            self.httpDict[TCPConnection][2] = (seq+httpData) % 4,294,967,295  #update next expected seq number
                            if (self.httpDict[TCPConnection][4] == False):   #do we already have the header?
                                for char in pkt[totalData-httpData:totalData]:  #going through http data byte by byte
                                    self.httpDict[TCPConnection][0] += char #add char to http data
                                if ('\r\n\r\n' in self.httpDict[TCPConnection][0]): #if we have full http header, get the header and only the header.
                                    temp = self.httpDict[TCPConnection][0].split('\r\n\r\n')
                                    self.httpDict[TCPConnection][0] = temp[0]
                                    self.httpDict[TCPConnection][4] = True  #we got requestHeader
                                    #check to see if we match any log rules
                                    http = makeReadable(self.httpDict[TCPConnection][0].lower())
                                    
                                    hostName = None
                                    for line in http:
                                        if line[0].lower() == 'host:':
                                            hostName = line[1].lower()
                                    if hostName == None:
                                        hostName = TCPConnection[0]

                                    for rule in self.rules:
                                        if (rule[0].lower() == 'log'):
                                            if (rule[2].lower() == hostName):               #if host name matches or the ip matches
                                                self.httpDict[TCPConnection][6] = True      #then log
                                            elif ('*' in rule[2].lower()):
                                                tempName = hostName
                                                ruleName = (rule[2].split('*'))[1]
                                                ruleName = ruleName.lower()
                                                while (len(tempName) >= len(ruleName)) and not self.httpDict[TCPConnection][6]:
                                                    if tempName == ruleName:
                                                        self.httpDict[TCPConnection][6] = True      #then log
                                                    tempName = tempName[1:]
                                            if self.httpDict[TCPConnection][6]:
                                                break
                elif (pkt_dir == PKT_DIR_INCOMING): #response
                    #try:
                    ip = str(struct.unpack('!B', pkt[12])[0]) + '.' + str(struct.unpack('!B', pkt[13])[0]) + '.' + str(struct.unpack('!B', pkt[14])[0]) + '.' + str(struct.unpack('!B', pkt[15])[0])
                    TCPConnection = (ip, struct.unpack('!H', pkt[lenIPHeader+2:lenIPHeader+4])[0])
                    seq, = struct.unpack('!L', pkt[lenIPHeader+4:lenIPHeader+8]) #get current seq
                    if (flagsTCP == 18):   #is a syn packet to get initial seq for responseSeq.
                        self.httpDict[TCPConnection][3] = seq+1
                        self.wrap = False
                    elif not (httpData == 0) and (TCPConnection in self.httpDict):   #continued data packets
                        if ((seq > self.httpDict[TCPConnection][3]) or (self.wrap and (seq < self.httpDict[TCPConnection][3]))): #if seq is greater than what we expected (out of order packet)
                            send = False    #drop packet
                        elif ((seq < self.httpDict[TCPConnection][3]) or (self.wrap and (seq < self.httpDict[TCPConnection][3]))): #if seq is less (retransmitted packet)
                            #Let it be sent, don't do anything in http
                            a = 1
                        else:   #seq is what we expected
                            tempSeq = seq+httpData % 4,294,967,295
                            if (tempSeq < self.httpDict[TCPConnection][3]):
                                self.wrap = True
                            else:
                                self.wrap = False
                            self.httpDict[TCPConnection][3] = (seq+httpData) % 4,294,967,295  #update next expected seq number
                            if (self.httpDict[TCPConnection][5] == False):   #do we already have the header?
                                for char in pkt[totalData-httpData:totalData]:  #going through http data byte by byte
                                    self.httpDict[TCPConnection][1] += char #add char to http data
                                if ('\r\n\r\n' in self.httpDict[TCPConnection][1]): #if we have full http header, get the header and only the header.
                                    temp = self.httpDict[TCPConnection][1].split('\r\n\r\n')
                                    self.httpDict[TCPConnection][1] = temp[0]
                                    self.httpDict[TCPConnection][5] = True  #we got requestHeader
                                if self.httpDict[TCPConnection][6]: #if a rule matched
                                    http = makeReadable(self.httpDict[TCPConnection][0].lower())
                                    hostName = None
                                    for line in http:
                                        if line[0].lower() == 'host:':
                                            hostName = line[1].lower()
                                    if hostName == None:
                                        hostName = TCPConnection[0]
                                    httpRequest = getRequestLog(makeReadable(self.httpDict[TCPConnection][0]))
                                    httpResponse = getResponseLog(makeReadable(self.httpDict[TCPConnection][1]))
                                    #write to log
                                    f = open('http.log', 'a')
                                    f.write(str(hostName) + ' ' + httpRequest + ' ' + httpResponse + '\n')
                                    f.flush()

                    elif (flagsTCP == 1):   #if the packet is to terminate connection
                        self.httpDict.pop(TCPConnection)    #remove connection
            if send and (pkt_dir == PKT_DIR_INCOMING):
                self.iface_int.send_ip_packet(pkt)
            elif send and (pkt_dir == PKT_DIR_OUTGOING):
                self.iface_ext.send_ip_packet(pkt)
        except:
            return

    def extractRules(self, config):
        rulesFile = open(config['rule'], 'r')
        rules = []
        for line in rulesFile:
            if line == '' or line[0] == '%' or line == '\n':
                pass
            else:
                parsedRule = line.split()
                rule = [x.lower() for x in parsedRule]
                rules.append(rule) #take the protocol, get lower case, add onto protocol list

        rules = rules[::-1]
        return rules

    def loadGeoIP(self, config):
        countries = []
        for rule in self.rules:
            if(len(rule[2]) == 2) and (not (rule[2] in countries)):
                countries.append(rule[2])

        geoList = []
        geoipdb = open('geoipdb.txt', 'r')
        for line in geoipdb:
            splitLine = line.split()
            if splitLine[2].lower() in countries:
                currentNode = CountryNode(splitLine[0].lower(), splitLine[1].lower(), splitLine[2].lower()) #just in case, doesn't hurt to make everything lower
                geoList.append(currentNode)
        return geoList

    #Makeshift ip_type identifier. Only used to categorize rules, so assume valid
    def ip_type(self, IP):
        if IP.lower() == 'any':
            return self.ANY
        if len(IP) == 2:
            return self.COUNTRYCODE
        parts = IP.split('/')
        if len(parts) > 1:
            return self.PREFIXIP
        return self.SINGLE

    #Defines port type. Only used to categorize rules, so assume valid
    def port_type(self, port):
        if port.lower() == 'any':
            return self.ANY
        parts = port.split('-')
        if len(parts) > 1:
            return self.RANGE
        return self.SINGLE


class CountryNode:
    def __init__(self, minIP, maxIP, countryCode):
        self.minIP = minIP
        self.maxIP = maxIP
        self.countryCode = countryCode

def getCountryCode(IP, geoList):
    lower = 0
    upper = len(geoList)
    while(lower < upper):
        try:
            mid = (lower+upper)/2
            currentGeo = geoList[mid]
            if compareIP(IP, currentGeo.minIP) and compareIP(currentGeo.maxIP, IP): #within the currentGeo range
                return currentGeo.countryCode
            elif lower == mid:
                return None #reached the end of the search, nothing found
            elif compareIP(IP, currentGeo.minIP) and (not compareIP(currentGeo.maxIP, IP)): #greater than currentGeo range
                lower = mid            
            elif (not compareIP(IP, currentGeo.minIP)) and compareIP(currentGeo.maxIP, IP): #less than currentGeo range
                upper = mid
        except:
            return None
    return None     #covering my bases, this shouldn't run if everything is correct

#true if first IP is greater or equal to secondIP
def compareIP(firstIP, secondIP):
    firstIP = firstIP.split('.')
    secondIP = secondIP.split('.')
    for i in xrange(0,4):
        if int(firstIP[i]) > int(secondIP[i]):
            return True
        elif int(firstIP[i]) < int(secondIP[i]):
            return False         
    return True # All numbers are equal

def inRange(interval, port):
    interval = interval.split('-')
    return (int(interval[0]) <= port) and (int(interval[1]) >= port)

def create_rst_packet(pkt):
    rst = ""
    ip_header_length, = struct.unpack('!B', pkt[0]) #IHL on IP Header
    ip_header_length = (ip_header_length & 0b00001111) * 4 #gets the offset to the tcp, udp, icmp headers
    pkt_src = pkt[12:16]
    pkt_dst = pkt[16:20]
    version_and_ihl = struct.pack('!B', 69)
    rst = version_and_ihl + pkt[1] + struct.pack('!H',40) #First row
    rst = rst + pkt[4:8] #row 2
    rst = rst + struct.pack('!B', 64) #TTL
    rst = rst + pkt[9] #protocol
    rst = rst + struct.pack('!H', 0) #checksum placeholder
    rst = rst + pkt_dst
    rst = rst + pkt_src
    if len(rst) != 20:
        print "ip length isn't 20, it is %d" % len(rst)
    rst = rst[0:10] + generate_checksum(rst) + rst[12:20]
    src_port = pkt[ip_header_length:ip_header_length+2]
    dst_port = pkt[ip_header_length+2:ip_header_length+4]
    seq_num, = struct.unpack('!L', pkt[ip_header_length+4:ip_header_length+8])
    tcp = dst_port + src_port + struct.pack('!L', 100) #first 2 rows
    tcp = tcp + struct.pack('!L', seq_num+1) #ACK num
    tcp = tcp + struct.pack('!B', 80) #offset + reserved set to all 0's
    tcp = tcp + struct.pack('!B', 20) #tcp flags
    tcp = tcp + pkt[ip_header_length+14:ip_header_length+16] #window
    tcp = tcp + struct.pack('!H', 0) #checksum placeholder
    tcp = tcp + pkt[ip_header_length+18:ip_header_length+20] #urgent pointer
    if len(tcp) != 20:
        print "tcp length isn't 20, it is %d" % len(tcp)
    pseudo_header = pkt_dst+pkt_src+struct.pack('!B',0)+struct.pack('!B',6)+struct.pack('!H',20)
    tcp = tcp[0:16] + generate_checksum(pseudo_header+tcp) + tcp[18:20]
    rst = rst + tcp
    return rst

def create_dns_packet(pkt, qname_begin, qname_index):
    ip_header_length, = struct.unpack('!B', pkt[0]) #IHL on IP Header
    ip_header_length = (ip_header_length & 0b00001111) * 4
    pkt_src = pkt[12:16]
    pkt_dst = pkt[16:20]
    ip = struct.pack('!B', 69)+pkt[1] + struct.pack('!H', 0) #keep total length 0 for now
    ip = ip + pkt[4:8]
    ip = ip + struct.pack('!B', 64) + pkt[9] + struct.pack('!H', 0) #2 byte empty checksum
    ip = ip + pkt_dst + pkt_src
    if len(ip) != 20:
        print "dns ip length isn't 20, it is %d" % len(ip)
    udp = pkt[ip_header_length+2:ip_header_length+4] + pkt[ip_header_length:ip_header_length+2]
    udp = udp + struct.pack('!H', 0) + struct.pack('!H',0)
    dns = pkt[ip_header_length+8:ip_header_length+10]
    qr, = struct.unpack('!B', pkt[ip_header_length+10])
    qr = (qr | 0b10000000)
    qdcount = pkt[ip_header_length+12:ip_header_length+14]
    ancount = struct.pack('!H', 1)
    dns = dns + struct.pack('!B', qr) + struct.pack('!B', 0) +  qdcount + ancount + pkt[ip_header_length+16:ip_header_length+20]
    if qname_begin != ip_header_length+20:
        print "qname_begin doesn't match ip_header_count"
    qname = pkt[qname_begin:qname_index+1]
    qtype = pkt[qname_index+1:qname_index+3]
    qclass = pkt[qname_index+3:qname_index+5]
    dns = dns + qname + qtype + qclass
    dns = dns + qname + qtype + qclass + struct.pack('!L',1) + struct.pack('!H',4) #answer section
    rdata = socket.inet_aton("54.173.224.150")
    dns = dns + rdata
    udp = udp[0:4] + struct.pack('!H', len(dns)+8) + udp[6:8]
    ip = ip[0:2] + struct.pack('!H',len(ip+udp+dns)) + ip[4:20]
    ip = ip[0:10] + generate_checksum(ip) + ip[12:20]
    return ip+udp+dns

def generate_checksum(data):
    total = 0
    index = 0
    while index < len(data) - 1:
        total = total + struct.unpack('!H', data[index:index+2])[0]
        index = index + 2
    while (total >> 16) != 0:
        total = (total & 0xffff) + (total >> 16)
    total = (~total) & 0xffff
    checksum = struct.pack('!H', total)
    return checksum

####Proj3b functions####
def makeReadable(rawHttp):
    rawHttp = rawHttp.split('\r\n')   #split HTTP string by '\n' (lines).
    for i in range(len(rawHttp)):
        rawHttp[i] = rawHttp[i].split(' ')  #split by space now each rawHTTP[i] is an array of words.
    return rawHttp

#parse HTTP request to get method, path, version
def getRequestLog(http):
    return http[0][0] + ' ' + http[0][1] + ' ' + http[0][2]

#parse HTTP response to get status_code and object_size
def getResponseLog(http):
    object_size = '-1'
    for line in http:
        if line[0].lower() == 'content-length:':
            object_size = line[1]
    return http[0][1] + ' ' + object_size
##########################

