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

import paho.mqtt.client as mqtt #import the client
import time

class Subscriber():
    """ The Sub class """
    def Sub(self):
        self.brokerAddress = "localhost"
        client = mqtt.Client("Broker")
        client.reinitialise()
        def on_message(client, userdata, message):
            #print("The message received is " ,str(message.payload.decode("utf-8")))
            #print("The topic=",message.topic)
            #data = str(message.payload.decode("utf-8"))
            print(message.payload)
            #print("message qos=",message.qos)
            #print("message retain flag=",message.retain)
        client.on_message=on_message #attach function to callback
        client.connect(self.brokerAddress, 1883, 60) #connect to broker
        client.loop_start() #start the loop
        client.subscribe("MCSC")
        print("[*] Waiting for new publications ")
        time.sleep(50)
        client.loop_stop()
if __name__ == "__main__":
    S = Subscriber()
    S.Sub()


