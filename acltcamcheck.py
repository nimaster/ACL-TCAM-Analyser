__author__ = "Niall Masterson"
__author_email__ = "nimaster@cisco.com"
__copyright__ = "Copyright (c) 2022 Cisco Systems, Inc."

"""
THIS SCRIPT CALCULATES THE TCAM RESOURCES ON CISCO 8000 SERIES ROUTERS REQUIRED FOR A GIVEN ACCESS_LIST
COPY YOUR ACL TO A FILE CALLED sample-acl AND THEN RUN THE SCRIPT
"""


import math
import re

totaltcam = 0
rangetcam = 0

#PROTOCOL DICTIONARY IS USED TO TRANSLATE THE WELL-KNOWN PROTOCOL NAMES INTO THEIR RESPECTIVE PORT NUMBERS. IOS-XR AUTO-TRANSLATES THE PORT NUMBERS OF THESE WELL KNOW PROTOCOLS INTO THE PROTOCOL NAME IN THE ROUTER CONFIG. TRANSLATING IT BACK TO THE PORT NUMBER IS NEEDED IN THE SCRIPT IN ORDER TO CALCULATE THE TCAM ENTRIES FOR ACL LINES THAT USE THESE WELL-KNOWN PROTOCOLS ALONG WITH THE RANGE, LT OR GT OPTIONS. 

protocol = {'bgp': 179, 'chargen': 19, 'cmd': 514, 'daytime': 13, 'discard': 9, 'domain': 53, 'echo': 7, 'exec': 512, 'finger': 79, 'ftp': 21, 'ftp-data': 20, 'gopher': 70, 'hostname': 101, 'https': 443, 'indent': 113, 'irc': 194, 'klogin': 543, 'kshell': 544, 'ldp': 646, 'login': 513, 'lpd': 515, 'nntp': 119, 'pim-auto-rp': 496, 'pop2': 109, 'pop3': 110, 'radius': 1812, 'radius-acct': 1813, 'smtp': 25, 'snmp': 161, 'ssh': 22, 'sunrpc': 111, 'tacacs': 49, 'talk': 517, 'telnet': 23, 'time': 37, 'uucp': 540, 'whois': 43, 'www': 80, 'bfd': 3784, 'biff': 512, 'bootpc': 68, 'bootps': 67, 'discard': 9, 'dnsix': 195, 'echo': 7, 'isakmp': 500, 'mobile-ip': 434, 'nameserver': 42, 'netbios-dgm': 138, 'netbios-ns': 137, 'netbios-ss': 139, 'rip': 520, 'snmptrap': 162, 'syslog': 514, 'tftp': 69, 'who': 513, 'xdmcp': 177}

#THE CALC_RANGE FUNCTION WILL CALCULATE THE NUMBER OF TCAM ENTRIES NEEDED FOR ACL LINES THAT USE THE RANGE, LT OR GT OPTIONS TO DEFINE A RANGE OF TCP OR USP PORTS

def calc_range ():
    global rangetcam

#CHECK IF THE LOWEST NUMBER IN THE RANGE IS ODD. IF SO, THEN THIS NUMBER WILL CONSUME A SINGLE TCAM ENTRY BY ITSELF
#IF IT IS ODD THEN CREATE A NEW VARIABLE THAT WILL BE LOWEST EVEN NUMBER

    if (low % 2) == 0:
        evenlow = low
    else:
        evenlow = low +1
        #print(low, "will use one TCAM entry")
        rangetcam +=1

#CHECK IF THE HIGHEST NUMBER IN THE RANGE IS EVEN. IF SO, THEN THIS NUMBER WILL CONSUME A SINGLE TCAM ENTRY BY ITSELF
#IF IT IS EVEN THEN CREATE A NEW VARIABLE THAT WILL BE HIGHEST ODD NUMBER

    if (high % 2) == 0:
        oddhigh = high -1
        #print(high, "will use one TCAM entry")
        rangetcam +=1
    else:
        oddhigh = high

#CALCULATE THE RANGES OF VALUES THAT CAN BE COVERED BY THE SAME BITSTRING AND BITMASK THAT CAN BE COVERED BY A SINGLE TCAM ENTRY
#START WITH RANGES WHERE THE LOWER VALUE IS MORE THAN HALF OF THE HIGHER VALUE

    while (evenlow >= oddhigh/2 +1) and (evenlow < oddhigh):
        A = 0
        if evenlow == 0:
            break

        #CALCULATE THE 2^x VALUE THAT IS CLOSEST TO EVENLOW
        else:
            while A <= 16:
                aExp = math.pow(2, A)
                if evenlow >= aExp:
                    A +=1
                    B = int(aExp)
                else:
                    A = 17

            A = 0

            while A <= 16:
                if evenlow % B == 0:
                    break
                else:
                    B = int(B/2)
                    A += 1
            while B > oddhigh - evenlow +1:
                    B = int(B/2)
            rangetcam += 1
            #print(evenlow, "to", evenlow + B -1, "will use one TCAM entry")
            evenlow = evenlow + B

#NEXT LOOK AT RANGES WHERE THE LOWER VALUE IS LESS THAN HALF OF THE HIGHER VALUE. AND CALCULATE THE RANGES OF VALUES WITHIN THAT RANGE THAT CAN BE COVERED BY THE SAME BITSTRING AND BITMASK WHICH CAN SHARE THE SAME TCAM ENTRY. THIS WILL CALCULATE THE TCAM ENTRIES UP UNTIL A VALUE THAT IS HALF OF THE HIGH VALUE.
    while evenlow < oddhigh/2 +1:
        A = 0
        if evenlow == 0:
            break

        #CALCULATE THE 2^x VALUE THAT IS CLOSEST TO EVENLOW
        else:
            while A <= 16:
                aExp = math.pow(2, A)
                if evenlow >= aExp:
                    A +=1
                    B = int(aExp)
                else:
                    A = 17

            A = 0
    
            while A <= 16:
                if evenlow % B == 0:
                    break
                else:
                    B = int(B/2)
                    A += 1
            rangetcam += 1
            #print(evenlow, "to", evenlow + B -1, "will use one TCAM entry")
            evenlow = evenlow + B

#FINALLY CALCULATE THE REMAINING TCAM ENTRIES FOR UP TO THE HIGH VALUE
    while oddhigh - evenlow > 0:
        diff = oddhigh - evenlow + 1
        A = 0

        #CALCULATE THE 2^x VALUE THAT IS CLOSEST TO DIFF
        while A <= 16:
            aExp = math.pow(2, A)
            if diff >= aExp:
                A +=1
                C = int(aExp)
            else:
                A = 17

        if C > 1:
            #print(evenlow, "to", evenlow + C -1, "will use one TCAM entry")
            rangetcam +=1
        else:
            #print(evenlow, "to", evenlow + C, " will use one TCAM entry")
            rangetcam +=1
        evenlow = evenlow + C

    #print("Total TCAM entries required for range", low,"to", high, "is:", rangetcam)


#ACCESS THE FILE WITH THE ACL

f = open('sample-acl')
lines = f.readlines()

#REGEX PATTERNS DEFINED FOR PARSING THE ACL FILE

pattern1 = "deny ipv4"
denyipv4 = 0

pattern2 = "permit ipv4"
permitipv4 = 0

pattern3 = "deny udp"
denyudp = 0

pattern4 = "permit udp"
permitudp = 0

pattern5 = "deny tcp"
denytcp = 0

pattern6 = "permit tcp"
permittcp = 0

pattern7 = "range"

pattern8 = "permit tcp .* eq"

pattern9 = "permit udp .* eq"

pattern10 = "permit icmp"
permiticmp = 0

pattern11 = "deny icmp"
denyicmp = 0

pattern12 = ".*any$"

pattern13 = ".*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"

pattern14 = "(permit|deny) [0-9]{1,3}"
permitdenyipp = 0

pattern15 = "(permit|deny) (ahp|eigrp|esp|gre|igmp|ipinip|nos|ospf|pcp|pim|rsvp|sctp|vrrp)"

pattern16 = " lt "

pattern17 = " gt "

pattern18 = "[a-z]"

#PARSE EACH ACL LINE TO DETERMINE HOW MUCH TCAM IT WILL USE. ACL LINES WITH THE RANGE, LT AND GT OPTIONS WILL CALL THE CALC_RANGE FUNCTION DEFINED ABOVE

for line in lines:
    for match in re.finditer(pattern1, line):
        denyipv4 += 1
        totaltcam += 1
    for match in re.finditer(pattern2, line):
        permitipv4 += 1
        totaltcam += 1
    for match in re.finditer(pattern3, line):
        if "range" in line:
            pass
        elif " lt " in line:
            pass
        elif " gt " in line:
            pass
        else:
            denyudp += 1
            totaltcam += 1
    for match in re.finditer(pattern4, line):
        if "range" in line:
            pass
        elif " lt " in line:
            pass
        elif " gt " in line:
            pass
        else:    
            permitudp += 1
            totaltcam += 1
        for match in re.finditer(pattern9, line):
            permittcp += 1
            totaltcam += 1
    for match in re.finditer(pattern5, line):
        if "range" in line:
            pass
        elif " lt " in line:
            pass
        elif " gt " in line:
            pass
        elif "established" in line:
            denytcp += 2
            totaltcam +=2
        else:
            denytcp += 1
            totaltcam += 1    
    for match in re.finditer(pattern6, line):
        if "range" in line:
            pass
        elif " lt " in line:
            pass
        elif " gt " in line:
            pass
        elif "established" in line:
            permittcp += 2
            totaltcam += 2
        else:
            permittcp += 1
            totaltcam += 1
        for match in re.finditer(pattern8, line):
            permittcp += 1
            totaltcam += 1
    for match in re.finditer(pattern7, line):
        parse1 = line.split('range ')
        parse2 = parse1[1].split(' ')
        low = parse2[0]
        high = parse2[1]
        high = high.strip()
        if re.match(pattern18, low):
            low = protocol[low]
        else:
            low = int(low)
        if re.match(pattern18, high):
            high = protocol[high]
        else:
            high = int(high)
        calc_range()
        if "permit" in line:
            rangetcam = rangetcam + 1
        else:
            pass
    for match in re.finditer(pattern16, line):
        parse1 = line.split('lt ')
        low = 0
        high = parse1[1]
        high = high.strip()
        if re.match(pattern18, high):
            high = protocol[high] -1
        else:
            high = int(high) -1
        #print(low)
        #print(high) 
        calc_range()
        if "permit" in line:
            rangetcam = rangetcam + 1
        else:
            pass
    for match in re.finditer(pattern17, line):
        parse1 = line.split('gt ')
        low = parse1[1]
        low = low.strip()
        high = 65535
        if re.match(pattern18, low):
            low = protocol[low] +1
        else:
            low = int(low) +1
        #print(low)
        #print(high)
        calc_range()
        if "permit" in line:
            rangetcam = rangetcam + 1
        else:
            pass
    for match in re.finditer(pattern10, line):
        permiticmp += 2
        totaltcam += 2
        for match in re.finditer(pattern12, line):
            permiticmp -= 1
            totaltcam -= 1
        for match in re.finditer(pattern13, line):
            permiticmp -= 1
            totaltcam -= 1
    for match in re.finditer(pattern11, line):
        denyicmp += 1
        totaltcam += 1
    for match in re.finditer(pattern14, line):
        permitdenyipp += 1
        totaltcam += 1
    for match in re.finditer(pattern15, line):
        permitdenyipp += 1
        totaltcam += 1

totaltcam = totaltcam + rangetcam

totaltcam += 1

#PRINT OUTPUT

print("Number of deny ipv4 entries:", denyipv4)
print("Number of permit ipv4 entries:", permitipv4)
print("Number of deny udp entries:", denyudp)
print("Number of permit udp entries:", permitudp)
print("Number of deny tcp entries:", denytcp)
print("Number of permit tcp entries:", permittcp)
print("Number of range entries:", rangetcam)
print("Number of permit icmp entries:", permiticmp)
print("Number of deny icmp entries:", denyicmp)
print("Number of permit or deny entries for other IP protocols:", permitdenyipp)

print("Total narrow (160 bit) TCAM entries needed for this ACL is:", totaltcam)

