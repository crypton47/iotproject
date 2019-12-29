
"""
Master CyberSecurite & CyberCriminalite  - Ensa Tanger
Author : BATALI OUALID 
Date : 14 dec 2019
Python version : Python 2.
_____________________________________________________________________________
 GOAL OF THE IMPLEMENTATION:  TEST COMUNICATION PHASE : Security Level 1 
 Where publish messages are protected against tampering and modification. 
____________________________________________________________________________
Notes: 
- I used ECDSA as an alternative for Schnur Digitale Signature.
- Scripts successfuly worked on ipython version  5.8.1
"""

import cryptography
import random # for generating prime numbers for cryptographic parameters
import os
import time  # to create the timestamp of publications (avoid Replay Attacks)
from sympy import randprime
from random import randint
import paho.mqtt.client as mqtt #import the client
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization

class Publisher():
    #self.G =  # G is a point generator of the chosen elliptic curve
    def __init__(self):
        self.G = 5
        self.q = 5
        self.a = randint(0,self.q-1) # publishers private key for the Schnorr digital signature scheme 
        self.ID = self.a * self.G # the ID of the pulisher.

    def Request(self, T, ID, M):
        self.q = 14
        self.G = 5
        self.slevel = "SL1"
        self.M = M
        self.ID = ID 
        self.T = T
        self.t = str(time.strftime("%A %d %B %Y %H:%M:%S")) # the timestamp to prevent Replay Attacks
        self.d = randint(0, self.q-1) 
        self.R = self.d * self.G

        # To verify on the Broker side , we'll use : 
        # public_key = private_key.public_key()
        # public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        self.data0 = self.slevel+self.ID+self.T+self.M+self.t
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.serialized_public = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.serialized_public = str(self.serialized_public)
        self.e = self.private_key.sign(self.data0,ec.ECDSA(hashes.SHA256()))
        #self.z = self.d - self.e * self.a 
        self.sig = str(self.e)
        #self.sig  = str((self.z, self.e)) # The sig that insures the Authetication and Non-Repudiation of messages
        self.data = self.slevel+"*"+self.ID+"*"+self.T+"*"+self.M+"*"+self.t+"*"+self.sig+"*"+self.serialized_public
        return self.data
    def publishRequest(self, T, ID, M):
        self.brokerAddress = "localhost"
        client = mqtt.Client("P1")
        client.reinitialise()
        #client.on_message=on_message #attach function to callback
        print("[*] Connecting to the broker")
        client.connect(self.brokerAddress, 1883, 60) #connect to broker
        client.loop_start() #start the loop
        #print("Subscribing to topic","B")
        #client.subscribe("B")
        print("Publishing message to topic","MCSC")
        data = P.Request(T, ID, M)
        # data = P.Request("MCSC","47","IT WORKS")
        client.publish("B",data)
        client.loop_stop()


if __name__ == "__main__":
    P = Publisher()
    P.publishRequest("MCSC", "49","It Works")




