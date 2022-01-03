#!/bin/python3
'''
Title: update-fortress.py
Purpose: Update infosec-fortress
Author: James Smith (DFIRmadness)
Notes: This will help upgrade many of the core packages that will not get updated simply through apt.
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
LOG = FORTRESS_DIR + UPDATE_LOG

from datetime import datetime
from getpass import getpass
from hashlib import sha1
from os import geteuid,path,makedirs
from os.path import expanduser
from subprocess import run
from urllib.request import urlopen
from requests import get
from re import search

# Check that the user is root
def checkIfRoot():
    if geteuid() != 0:
            print(RED + '[!] You need sudo/root permissions to run this... exiting.' + NOCOLOR)
            exit(0)

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

# Update the REMnux Distribution
def upgradeREMnux():
    writeToLog('[+] Upgrading REMnux. Verify the hash from the site later.')
    try:
        run(['/usr/bin/wget https://REMnux.org/remnux-cli'],shell=True)
        run(['/usr/bin/mv remnux-cli remnux'],shell=True)
        run(['/usr/bin/chmod +x remnux'],shell=True)
        run(['/usr/bin/mv remnux /usr/local/bin'],shell=True)
        print('[*] Latest REMnux Binary intalled. Now using that to upgrade REMnux...')
        run(['/usr/local/bin/remnux upgrade --mode=addon'],shell=True)
        print('[*] REMnux upgraded...')
        writeToLog('[+] REMnux Added On (downloaded and ran).')
    except Exception as e:
        writeToLog('[-] Something went wrong during the REMnux install. Error: ' + str(e))

# Update SIFT
def upgradeSIFTPackages():
    print('[*] Locating latest SIFT binary...')
    writeToLog('[*] Finding latest SIFT Release.')
    try:
        latestLinkPage  = get('https://github.com/sans-dfir/sift-cli/releases/latest').text.splitlines()
        latestSIFTBinLine = [match for match in latestLinkPage if "sift-cli-linux" in match][0].split('"')[1]
        latestSIFTBin = 'https://github.com/' + latestSIFTBinLine
        #latestSIFTBin = search('https:.*sift-cli-linux',latestSIFTBinLine)[0]
        writeToLog('[+] latest SIFT BIN: ' + latestSIFTBin)
        print('[*] Found and downloaded ' + latestSIFTBin)
    except Exception as e:
        writeToLog('[-] latest SIFT Bin not found. Error: ' + str(e))
        return
    writeToLog('[*] Installing latest SIFT and upgrading packages.')
    try:
        run(['/usr/bin/curl -Lo /usr/local/bin/sift ' + latestSIFTBin],shell=True)
        run(['/usr/bin/chmod +x /usr/local/bin/sift'],shell=True)
        run(['/usr/local/bin/sift upgrade --mode=packages-only'],shell=True)
        print('[*] SIFT Packages upgraded.')
        writeToLog('[+] SIFT Packages upgraded (downloaded and ran).')
    except Exception as e:
        writeToLog('[-] Installation of SIFT Packages had an error. Error: '+str(e))

# Message to user
def messageToUser():
    print('[*] Upgrades of SIFT and REMnux Complete. Updrade your OS as normal...')

def main():
    checkIfRoot()
    startLogFile()
    upgradeREMnux()
    upgradeSIFTPackages()
    messageToUser()
    exit(0)

main()
if __name__== "__main__":
    main()