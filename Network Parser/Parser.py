"""
Filename: Parser.py
@author: Santosh Kumar Nunna (sn7916@rit.edu)
@version: 0.1
@dateModified: 02/28/2021

This code performs the parsing of different packets and their description.
The flow goes as below:
IPv4
    -TCP
    -UDP
    -ICMP
    -IGMP
ARP
802.3
    -STP
802.2
    -CDP
Time Complexity: O(n)
Space Complexity: O(n)
"""

from datetime import timedelta
import sys


class Parser:

    def __init__(self, inp_file):
        self.inp = inp_file
        self.dataDict = dict()
        self.data, self.prev, self.delta = None, None, 0
        self.maxPacket, self.minPacket = float("-inf"), float("inf")
        self.avgPacket = 0
        self.decodeFile()
        self.decodeParser()

    def decodeFile(self):
        """
        The decodeFile function takes in the file data and cleans it.
        End result of this function is to populate the data dict with
        timestamp key and the rest as value
        :return: None
        """
        # Open the input file and read data. The strip removes the unwanted \n\r
        with open(self.inp) as filePointer:
            data = filePointer.read().strip()
        # Splitting based on the common part
        # TO DO: Replace this with a regex
        data = data.split("+---------+---------------+----------+")
        for da in data:
            # Checking for empty strings
            if not da:
                continue
            # Modify the list element to a dictionary
            # (after removing empty strings in internal strings using filter)
            temp = list(filter(None, da.splitlines()))
            self.dataDict[temp[0].split()[0]] = temp[1][5:].replace("|", "")

    def macFinder(self):
        """
        This function works on the class variable data. It takes the first 6 packets of data
        and converts into the mac address format
        If the data is not valid it returns None else a valid string output
        :return:string or None
        """
        if self.data:
            mac = self.data[:12]
            self.data = self.data[12:]
            return ''.join(l + ':' * (n % 2 == 1) for n, l in enumerate(mac))[:-1]
        return None

    def hexToDec(self, val):
        """
        This function converts the hexadecimal value into an integer (decimal or base 10 value)
        and returns it.
        :param val: hexadecimal value
        :return: Integer
        """
        return int(val, 16)

    def deltaTime(self, key):
        """
        This function calculates the time difference between the arrival of two data packets.
        It works on the assumption of a previous data packet existence. If its not present the
        default value is sent else the difference is calculated and returned.
        :param key: timestamp of current data frame
        :return: time difference object (microseconds)
        """
        h, m, s = key.split(":")
        s = s.replace(',', '')
        h, m, s, ms = int(h), int(m), int(s[:2]), int(s[2:])
        new_key = timedelta(hours=h, minutes=m, seconds=s, microseconds=ms)
        if self.prev:
            self.delta = new_key - self.prev
        self.prev = new_key
        return self.delta

    def decodeIP(self):
        """
        This functions works on the class variable data. It picks the first 8 parts of the data and
        converts it into IP format. The formed couples are in hexa format and are converted into
        decimal format -> xxx.xxx.xxx.xxx
        :return: string
        """
        val = self.data[:8]
        self.data = self.data[8:]
        temp, i = list(), 0
        while i < len(val):
            temp.append(val[i:i + 2])
            i += 2
        return '.'.join(str(x) for x in list(map(lambda x: self.hexToDec(x), temp)))

    def decodeTCP(self):
        """
        This function performs the parsing and information decoding for the TCP header
        :return: None
        """
        print("----------------TCP header----------------")
        print("Source Port: ", self.hexToDec(self.data[:4]))
        print("Destination Port: ", self.hexToDec(self.data[4:8]))
        print("Sequence Number (raw): ", self.hexToDec(self.data[8:16]))
        print("Acknowledge Number (raw): ", self.hexToDec(self.data[16:24]))
        print("Window size value: ", self.hexToDec(self.data[28:32]))
        print("Checksum: 0x" + self.data[32:36])
        print("Urgent Pointer: ", self.hexToDec(self.data[37:41]))

    def decodeUDP(self):
        """
        This function performs the parsing and information decoding for the UDP header
        :return: None
        """
        print("----------------UDP header----------------")
        print("Souce Port: ", self.hexToDec(self.data[:4]))
        print("Destination Port: ", self.hexToDec(self.data[4:8]))
        print("Length: ", self.hexToDec(self.data[8:12]))
        print("Checksum: 0x" + self.data[12:16])

    def decodeIGMP(self):
        """
        This function performs the parsing and information decoding for the IGMP header
        :return: None
        """
        print("----------------IGMP header----------------")
        print("Membership Query: 0x" + self.data[:2])
        print("Checksum: 0x" + self.data[4:8])
        self.data = self.data[8:]
        print("Multicast Address: ", self.decodeIP())

    def decodeICMP(self):
        """
        This function performs the parsing and information decoding for the ICMP header
        :return: None
        """
        print("----------------ICMP header----------------")
        icmpTypeDict = {8: "Echo Request", 0: "Echo Reply", 3: "Destination Reachable", 11: "Time Exceeded"}
        if self.hexToDec(self.data[:2]) in icmpTypeDict:
            print("ICMP Type: ", icmpTypeDict[self.hexToDec(self.data[:2])])
        else:
            print("ICMP Type: Others")
        print("ICMP Code: ", self.hexToDec(self.data[2:4]))
        print("Checksum: 0x" + self.data[4:8])

    def ipv4Parse(self):
        """
        This function performs the parsing and information decoding for the IPv4 header.
        After parsing, calls the appropriate functions layer wise.
        :return: None
        """
        print("----------------IPv4 header----------------")
        tcp, udp, icmp, igmp = False, False, False, False
        # Version of the ethernet Type
        ver = int(self.data[0])
        # Word length
        word = int(self.data[1])
        print("Version: ", ver)
        # The total length is the product of ver and word
        print("Word_length: ", ver * word)
        # Working on ecn1 and ecn2, based on these printing the appropriate one
        ecn1 = self.hexToDec(self.data[2])
        ecn2 = self.hexToDec(self.data[3])
        print("Differentiated Services Field:\t", end='')
        if ecn1 + ecn2 == 0:
            print("00  Non ECN-Capable Transport, Non-ECT")
        elif ecn1 + ecn2 == 2:
            print("11  Congestion Encountered, CE")
        elif ecn1:
            print("10  ECN Capable Transport, ECT(0)")
        else:
            print("01  ECN Capable Transport, ECT(1)")
        # Total length of the bytes
        print("Total length:\t", self.hexToDec(self.data[4:8]))
        # Identification value
        print("Identification:\t0x" + self.data[8:12])
        flags = self.data[12:14]
        # fragment_offset
        print("Fragment Offset:\t", self.hexToDec(self.data[14:16]))
        # timeToLive
        print("Time to Live:\t", self.hexToDec(self.data[16:18]))
        # Protocol
        protocol = self.hexToDec(self.data[18:20])
        # Based on the protocol type the boolean value is set to call the functions at the end
        if protocol == 1:
            icmp = True
        elif protocol == 2:
            igmp = True
        elif protocol == 6:
            tcp = True
        elif protocol == 17:
            udp = True
        # header_checksum
        print("Header checksum:\t0x" + self.data[20:24])
        self.data = self.data[24:]
        print("Source Address:\t", self.decodeIP())
        print("Destination Address:\t", self.decodeIP())
        #  Based on the boolean values set above these functions are called to perform appropriate parsing
        if tcp:
            self.decodeTCP()
        if udp:
            self.decodeUDP()
        if icmp:
            self.decodeICMP()
        if igmp:
            self.decodeIGMP()

    def arpParse(self):
        """
        This function performs the parsing and information decoding for the ARP header
        :return: None
        """
        print("-----------------ARP header-----------------")
        # Hardware Dictionary to identify the hardware category
        hardwareDict = {1: "Ethernet", 6: "IEEE 802 Networks", 7: "ARCNET", 15: "Frame reply", 16: "ATM", 17: "HDLC",
                        18: "Fibre Channel", 19: "ATM", 20: "Serial Line"}
        print("Hardware Type: ", hardwareDict[self.hexToDec(self.data[:4])])
        if self.data[4:8] == "0800":
            print("Protocol Type: IPv4")
        else:
            print("Protocol Type: Unrecognized")
        print("Hardware Size: ", self.hexToDec(self.data[8:10]))
        print("Protocol Size: ", self.hexToDec(self.data[10:12]))
        if self.hexToDec(self.data[12:16]) == 1:
            print("Opcode: Request")
        else:
            print("Opcode: Reply")
        self.data = self.data[16:]
        print("Sender MAC address: ", self.macFinder())
        print("Sender IP address: ", self.decodeIP())
        print("Target MAC address: ", self.macFinder())
        print("Target IP address: ", self.decodeIP())

    def eight023ParseSTP(self):
        """
        This function performs the parsing and information decoding for the 802.3 header
        :return: None
        """
        print("----------------802.3 header----------------")
        if self.data[6:10] == "0000":
            print("Protocol Identifier: Spanning Tree Protocol")
        else:
            print("Protocol Identifier: Unrecognized")
        print("Root Bridge System ID Extension: ", self.hexToDec(self.data[18:20]))
        self.data = self.data[20:]
        print("Root Bridge System ID: ", self.macFinder())
        print("Root Path Cost: ", self.hexToDec(self.data[:8]))
        print("Bridge Priority: ", self.hexToDec(self.data[8:12]))
        self.data = self.data[12:]
        print("System ID: ", self.macFinder())
        print("Port Identifier: 0x" + self.data[:4])
        print("Message Age: ", self.hexToDec(self.data[4:8]))
        print("Max Age: ", self.hexToDec(self.data[8:12]))
        print("Hello Time: ", self.hexToDec(self.data[12:16]))
        print("Forward Delay: ", self.hexToDec(self.data[16:20]))

    def eight022ParseCDP(self):
        """
        This function performs the parsing and information decoding for the 802.2 header
        :return: None
        """
        print("----------------802.2 header----------------")
        print("Organization Code: 0x" + self.data[6:12])
        if self.data[12:16] == "2000":
            print("PID: CDP")
        else:
            print("PID: Unrecognized")
        print("Version: ", self.hexToDec(self.data[16:18]))
        print("TTL: " + str(self.hexToDec(self.data[18:20])) + " seconds")
        print("Checksum: 0x" + self.data[20:24])
        print("Device ID: 0x" + self.data[24:28])

    def ethernetLayer(self):
        """
        This is the preliminary function that does the initial parsing to identify MAC address and
        based on the header types calls the next functions. At the end prints out the max, min and avergae packet
        sizes of the given input file.
        :return: None
        """
        if self.data:
            print("-------------Ethernet header------------")
            print("Destination MAC address: ", self.macFinder())
            print("Source MAC address: ", self.macFinder())
            ether_type = self.data[:4]
            self.data = self.data[4:]
            # Ethernet type switch
            if ether_type == "0800":
                print("Type:\tIPv4")
                self.ipv4Parse()
            elif ether_type == "0806":
                print("Type:\tARP")
                self.arpParse()
            elif ether_type in ["01e3", "0026"]:
                if ether_type == "01e3":
                    print("Type:\t802.2")
                    self.eight022ParseCDP()
                else:
                    print("Type:\t802.3")
                    self.eight023ParseSTP()
        else:
            print("Data Error")

    def decodeParser(self):
        """
        The decode Parser is the looping function on the entire data
        Everytime the data is set to the class variable and the processing is done.
        :return: None
        """
        for key in self.dataDict:
            self.data = self.dataDict[key]
            print("Timestamp:\t", key)
            print("Delta Time:\t", end='')
            print(self.deltaTime(key))
            dataLen = len(self.data)
            print("Number of packets: " + str(dataLen) + " bytes")
            self.avgPacket += dataLen
            self.maxPacket = max(self.maxPacket, dataLen)
            self.minPacket = min(self.minPacket, dataLen)
            self.ethernetLayer()
            print('\n\n')
        print("Maximum packet size in the data set: " + str(self.maxPacket) + " bytes")
        print("Minimum packet size in the data set: " + str(self.minPacket) + " bytes")
        print("Average packet size in the data set: " + str(self.avgPacket / len(self.dataDict)) + " bytes")


if __name__ == '__main__':
    args = sys.argv
    if len(args) < 2:
        print("Usage: python Parser.py filename | Example: python Parser.py 'data.txt'")
    else:
        obj = Parser(args[1])
