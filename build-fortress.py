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
14. enum4linux https://github.com/cddmp/enum4linux-ng
14. display fortress artwork
'''

# Globals
PKG_MGR = 'apt'
FORTRESS_DIR = '/opt/infosec-fortress/'
BUILD_LOG = 'build-fortress.log'
LOG = FORTRESS_DIR + BUILD_LOG

# Minimal Package list to get started
starterPackagesList = [
    'net-tools',
    'curl',
    'git'
]

# List of packages to have APT install. Change if you want. You break it you buy it.
aptPackageList = [
    'chromium-browser',
    'tmux',
    'torbrowser-launcher',
    'nmap',
    'smbclient',
    'locate',
    'radare2',
    'radare2-cutter',
    'snort',
    'clamav',
    'dirb',
    'gobuster',
    'nikto'
]

# List of packages to have SNAP install. Change if you want. You break it you buy it.
snapPackageList = [
    'sqlmap',
    'code',
    'zaproxy'
    ]

########################################################
# Colors
GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
NOCOLOR = '\033[m'

from datetime import datetime
from os import geteuid, path
from subprocess import run
from os import geteuid,mkdir
from urllib.request import urlopen

# Check that the user is root
if geteuid() != 0:
        print(RED + '[!] You need sudo/root permissions to run this... exiting.' + NOCOLOR)
        exit(0)

# Check for internet connection
try:
    check = urlopen('https://www.google.com', timeout=3.0)
    print(GREEN +'[+] Internet connection looks good!' + NOCOLOR)
except:
    print(RED + '[-] Internet connection looks down. You will need internet for this to run (most likely). Fix and try again.' + NOCOLOR)
    exit(1)

print('[!] This script requires user input once or twice.\n\
[!] It is not completely "Set and Forget".')
nullInput = input('Hit Enter.')

def createFortressDir(FORTRESS_DIR):
    print('[*] Creating InfoSec Fortress Dir at:',FORTRESS_DIR)
    try:
        mkdir(FORTRESS_DIR)
    except FileExistsError:
        print('[i] ' + FORTRESS_DIR + ' already exists. Continuing.')
    except Exception as e:
        print('[-] Error creating the ' + FORTRESS_DIR + '. Error ' + str(e))

def startLogFile():
    try:
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        if not path.isfile(LOG):
            with open(LOG, 'a') as log:
                log.write(now + " - Log Started.\n")
            return('Succeeded')
        else:
            with open(LOG, 'a') as log:
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
    if '[+]' in stringToLog:
        print(GREEN + stringToLog + NOCOLOR)
    elif '[-]' in stringToLog:
        print(RED + stringToLog + NOCOLOR)
    elif '[i]' in stringToLog + NOCOLOR:
        print(YELLOW + stringToLog + NOCOLOR)
    else:
        print(stringToLog)

def buildStarterPackageList():
    listOfPackagesCommand = ''
    for package in starterPackagesList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

def buildAptPackageList():
    listOfPackagesCommand = ''
    for package in aptPackageList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

def buildSnapPackageList():
    listOfPackagesCommand = ''
    for package in snapPackageList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

# apt update
def updateOS():
    #writeToLog('[+] Beginning OS updates...')
    try:
        run(['/usr/bin/apt','update'])
    except Exception as e:
        writeToLog('[-] APT Updating failed. Fix and try again. Error:',str(e))
        exit(1)
    try:
        run(['/usr/bin/apt','upgrade','-y'])
    except Exception as e:
        writeToLog('[-] APT Updating failed. Fix and try again. Error:',str(e))
        exit(1)
    try:
        run(['/usr/bin/apt','dist-upgrade','-y'])
    except Exception as e:
        writeToLog('[-] APT Updating failed. Fix and try again. Error:',str(e))
        exit(1)

# Minimal packages
def installStarterPackages():
    starterPackages = buildStarterPackageList()
    writeToLog('[*] Attempting installation of the following starter packages: ' + starterPackages)
    try:
        run(['/usr/bin/apt install -y ' + starterPackages],shell=True)
        writeToLog('[+] Starter Packages installed.')
    except Exception as e:
        writeToLog('[-] Starter Packages installation failed:',str(e))

# the REMnux Distribution
def installREMnux():
    writeToLog('[+] Installing REMnux. This will take quite awhile. Verify the hash from the site later.')
    try:
        run(['/usr/bin/wget https://REMnux.org/remnux-cli'],shell=True)
        run(['/usr/bin/mv remnux-cli remnux'],shell=True)
        run(['/usr/bin/chmod +x remnux'],shell=True)
        run(['/usr/bin/mv remnux /usr/local/bin'],shell=True)
        run(['/usr/local/bin/remnux install --mode=addon'],shell=True)
    except Exception as e:
        writeToLog('[-] Something went wrong during the REMnux install. Error: ' + str(e))

# install base packages
def installBasePackages():
    print('[i] If Wireshark asks - say YES non-super users can capture packets.\n\
    [i] When snort asks about a monitoring interface enter lo.\n\
    [i] Setting the interface to "lo" (no quotes) sets it for local use.')
    nullInput = input('Hit Enter.')
    aptPackages = buildAptPackageList()
    snapPackages = buildSnapPackageList()
    writeToLog('[*] Attempting installation of the following ATP packages: ' + aptPackages)
    try:
        run(['/usr/bin/apt install -y ' + aptPackages],shell=True)
        writeToLog('[+] APT Packages installed.')
    except Exception as e:
        writeToLog('[-] APT Packages installation failed:',str(e))
    writeToLog('[*] Attempting installation of the following Snap Packages: ' + snapPackages)
    try:
        run(['/usr/bin/snap install --classic ' + snapPackages],shell=True)
        writeToLog('[+] APT Packages installed.')        
    except Exception as e:
        writeToLog('[-] Snap packages installation failed:',str(e))

# Metasploit Framework
def installMSF():
    writeToLog('[+] Installing Metasploit Framework.')
    try:
        run(['/usr/bin/curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall'],shell=True)
        run(['/usr/bin/chmod 755 msfinstall'],shell=True)
        run(['./msfinstall'],shell=True)
        writeToLog('[+] MSF Installed Successfully.')
    except Exception as e:
        writeToLog('[-] Something went wrong during the MSF install. Error: ' + str(e))


# Install wordlists
    # Git clone the default wordlists
    # Add Rockyou2021

#Install exploit-db

# Burp Suite


# ZAP
# Print this feature may break. Go to and grab the latest install run dpkg -i 
# Scrape view-source:https://www.zaproxy.org/download/ for linux and grab the tar.gz or download.stable.nix
#def installZAP():
#    zapLatestSite = 'https://github.com/zaproxy/zaproxy/releases/latest'
#    zapDownloadSite = urlopen(zapLatestSite).read().decode('utf-8').split('\n')
#    zapDownloadLinksList = []
#    for line in zapDownloadSite:
#        if 'href' in line and 'Linux' in line:
#            zapDownloadLinksList.append(line)
#    zapForLinuxTAR = zapDownloadLinksList[0].split('"')[1]
#    run(['/usr/bin/wget ' + zapForLinuxTAR + ' -O /tmp/zap.tar.gz'],shell=True)
#    run(['/usr/bin/tar -xzvf /tmp/zap.tar.gz -C /tmp/ZAP'],shell=True)
# This effort was stopped as it seems best to install from Snap then let it update

# ghidra (Pronounced Gee-druh)
# I think this comes with REMnux


# log2Timeline

# elasticsearch containers

# powershell Core

# display fortress artwork

# Reboot - wait for null input as announcement to user

def main():
    createFortressDir(FORTRESS_DIR)
    startLogFile()
    updateOS()
    installStarterPackages()
    installREMnux()
    installBasePackages()
    installMSF()


#main()
#if __name__== "__main__":
#    main()