#!/bin/python3
'''
Title: build-fortress.py
Purpose: Build the infosec-fortress
Author: James Smith (DFIRmadness)
Notes: Beta
Version: 0.1

Functions:
1. apt update
2. dist upgrade
3. install base packages
4. create /opt/infosec-fortress
5. Metasploit Framework
6. Burp Suite
7. ZAP
8. VS Code
9. ghidra (Pronounced Gee-druh)
10. the REMnux Distribution
11. log2Timeline
12. elasticsearch containers
13. powershell Core
14. display fortress artwork
'''

# Globals
PKG_MGR = 'apt'
FORTRESS_DIR = '/opt/infosec-fortress'
BUILD_LOG = 'build-fortress.log'

# List of packages to have APT install. Change if you want. You break it you buy it.
aptPackageList = [
    'pkg1',
    'pkg2'
]

# List of packages to have SNAP install. Change if you want. You break it you buy it.
snapPackageList = [
    'pkg1',
    'pkg2'
]

def startLogFile():
    try:
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        if not path.isfile(BUILD_LOG):
            with open(BUILD_LOG, 'a') as log:
                log.write(now + " - Log Started.\n")
            return('Succeeded')
        else:
            with open(BUILD_LOG, 'a') as log:
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

def buildAptPackageList():
    listOfPackagesCommand = ''
    for package in aptPackageList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

def buildSnapPackageList():
    listOfPackagesCommand = ''
    for package in aptPackageList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

# apt update

# dist upgrade

# install base packages

# create /opt/infosec-fortress

# Metasploit Framework

# Burp Suite

# ZAP

# VS Code

# ghidra (Pronounced Gee-druh)

# the REMnux Distribution

# log2Timeline

# elasticsearch containers

# powershell Core

# display fortress artwork