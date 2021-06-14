#!/bin/python3
'''
Title: update-fortress.py
Purpose: Update infosec-fortress
Author: James Smith (DFIRmadness)
Notes: Not really all that necessary
Version: 0.1

Functions:
1. apt update
2. snap update
3. REMnux update
4. Update other packages
'''

PKG_MGR = 'apt'
FORTRESS_DIR = '/opt/infosec-fortress'
UPDATE_LOG = 'update-fortress.log'



def startLogFile():
    try:
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        if not path.isfile(UPDATE_LOG):
            with open(UPDATE_LOG, 'a') as log:
                log.write(now + " - Log Started.\n")
            return('Succeeded')
        else:
            with open(UPDATE_LOG, 'a') as log:
                log.write(now + " - Log Started. Strange, the log file appears to exist already?  Continuing anyways.\n")
            return('Succeeded')
    except:
        return('Failed')
        # For now just simply exit here
        exit(1)

def writeToLog(stringToLog):
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(LOG, 'a') as log:
        log.write(now + " - " + stringToLog + '\n')