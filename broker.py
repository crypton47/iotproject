
"""
Master CyberSecurite & CyberCriminalite  - Ensa Tanger
Author : BATALI OUALID 
Date : 14 dec 2019
Python version : 2.7.17.
_____________________________________________________________________________
 GOAL OF THE IMPLEMENTATION:  TEST COMUNICATION PHASE : Security Level 1 
 Where publish messages are protected against tampering and modification. 
____________________________________________________________________________
Notes: 
- I used ECDSA as an alternative for Schnur Digitale Signature.
- Scripts successfuly worked on Ipython version  5.8.1 (Python 2.7.17)
"""

import cryptography, random, os, time , sqlite3, time 
from sympy import randprime
from random import randint
import paho.mqtt.client as mqtt 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec , utils
from cryptography.hazmat.primitives import serialization , hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class Broker():
    """ The Broker Class """
    # In the setup phase the Broker generate the Rabin parametres 
    # the prime numbers r and s 
    # PKBroker = n = r . s 
    # publicKey = (PKBroker,KBroker) 
    G = 100
    q = 9
    numbertopics = 0 

    def __init__(self, db):
        self.r = randprime(2,232345245)
        self.s = randprime(2,5684567356)
        self.PKBroker = self.r * self.s # The pulic key of the Broker
        self.kBroker = randint(0,self.q-1) 
        self.KBroker = self.kBroker * self.G
        self.createdb(db)

    def parameters(self):
        print(self.r, self.s, self.numbertopics)
    
    def CheckSignature(self,data, public_key, signature):
        """ Checking the ID and topic """
        self.flag = False
        self.data = data
        self.public_key = public_key
        self.signature = signature
        try:
            public_key.verify(signature,data, ec.ECDSA(hashes.SHA256()))
            Flag = True
            print("VERIFICATION OF THE SIGNATURE :\nAuthentification succeed ! ")
        except:
            print("VERIFICATION OF THE SIGNATURE :\nAuthentification failled !")
            Flag = False
        return Flag
        # If the signature is not valid, the broker will drop the message.
        # If the signature is valid, the broker will send the message to subscribers
        # based on topics.
    def sendToSub(self,T,M):
        """ what the broker will send to subscrier """
            #def publishRequest(self, T, ID, M):
        self.brokerAddress = "localhost"
        client = mqtt.Client("P2")
        client.reinitialise()
        print("[*] Publishing the message to subscriber")
        client.connect(self.brokerAddress, 1883, 60) #connect to broker
        client.loop_start() #start the loop
        #print("Subscribing to topic","B")
        #client.subscribe("B")
        print("Publishing message to topic",self.T)
        # data = P.Request("MCSC","47","IT WORKS")
        client.publish(T,M)
        client.loop_forever()
    
    

    def createdb(self, db):
        try:
            sqliteConnection = sqlite3.connect(db)
            sqlite_create_table_query = """ CREATE TABLE publishers(
                                    publisherID TEXT PRIMARY KEY,
                                    topic TEXT NOT NULL UNIQUE);"""
            cursor = sqliteConnection.cursor()
            print("Successfully connected to sqlite database.db")
            cursor.execute(sqlite_create_table_query)
            sqliteConnection.commit()
            print("Table ID/Topic created")
            cursor.close()
        except sqlite3.Error as error:
            print("Error while creating a sqlite table",error)
        finally:
            if(sqliteConnection):
                sqliteConnection.close()

    def addPublisher(self,db,publisherID,topic):
        try:
            sqliteConnection = sqlite3.connect(db)
            sqlite_insert_query = """INSERT INTO `publishers` ('publisherID','topic') VALUES (?,?)"""
            data_tuple = (publisherID,topic)
            cursor = sqliteConnection.cursor()
            print("Successfully connected to sqlite")
            cursor.execute(sqlite_insert_query, data_tuple)
            sqliteConnection.commit()
            print("the new ID publisher and topic are inserted")
            cursor.close()
            self.numbertopics += 1
        except sqlite3.Error as error:
            print("Error while creating a sqlite table",error)
        finally:
            if(sqliteConnection):
                sqliteConnection.close()
                print("Sqlite connection is closed")
    def runBroker(self):
        global data 
        data = ''
        self.brokerAddress = "localhost"
        client = mqtt.Client("Broker")
        client.reinitialise()
        def on_message(client, userdata, message):
            global data 
            #print("The message received is " ,str(message.payload.decode("utf-8")))
            #print("The topic=",message.topic)
            #data = str(message.payload.decode("utf-8"))
            data = message.payload
            #print("message qos=",message.qos)
            #print("message retain flag=",message.retain)
        client.on_message=on_message #attach function to callback
        print("[*] The Broker is running ")
        client.connect(self.brokerAddress, 1883, 60) #connect to broker
        client.loop_start() #start the loop
        client.subscribe("B")
        print("Waiting for Publishers Requests")
        while data == '':
            time.sleep(1)
        data = data.split('*')
        self.SL1 = data[0] # security level
        self.ID = data[1] # the publisher ID
        self.T = data[2] # the topic
        self.M = data[3] # the message Data
        self.t = data[4] # the timestamp
        self.sig = data[5] # signature
        self.pem = data[6] # public key serialised ! 
        print("----->PUBLISHER REQUEST DATA INFO:\n[*]SecurityLEVEL: {}\n[*]ID = {}\n[*]Topics = {}\n[*]Message = {}\n[*]tampstamp = {}\n[*]Signature = {}\nPublic Key: {}".format(self.SL1,self.ID,self.T,self.M,self.t,self.sig,self.pem))
        # Now we should add the publisherID and topic to the database.
        time.sleep(3)
        B.addPublisher('database.db', self.ID, self.T)
        self.public_key = load_pem_public_key(self.pem,backend=default_backend())
        DataToVerify = self.SL1+self.ID+self.T+self.M+self.t
        Flag = B.CheckSignature(DataToVerify, self.public_key, self.sig)
        return Flag,self.T,self.M
        client.loop_forever()

if __name__ == "__main__":
    B = Broker('database.db')
    infos = B.runBroker()
    if infos[0] :
        B.sendToSub(infos[1],infos[2])

