#!/bin/python3
'''
Title: build-fortress.py
Purpose: Build the infosec-fortress
Author: James Smith (DFIRmadness)
Contributors: Check the github page.
Notes: Beta
Version: 0.1
Usage: ./build-fortress.py

Functions:
+ apt update
+ dist upgrade
+ install base packages
+ create /opt/infosec-fortress
+ start log
+ install starter packages (min. pkgs to let script run)
+ install the REMnux Distribution
+ install SIFT
+ install base security packages
+ install Metasploit Framework
+ install wordlists
+ install and update exploitdb (searchsploit)
+ log2Timeline
+ elasticsearch containers
+ powershell Core (turns out its part of REMnux)
+ install impacket
+ install enum4linux
+ enum4linux https://github.com/cddmp/enum4linux-ng
+ display message about updating ZAP and Burp after reboot
+ display log
+ display fortress artwork
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
    'tmux',
    'torbrowser-launcher',
    'nmap',
    'smbclient',
    'locate',
    'radare2-cutter',
    'snort',
    'dirb',
    'gobuster',
    'medusa',
    'masscan',
    'whois',
    'libjenkins-htmlunit-core-js-java',
    'autopsy',
    'hashcat',
    'kismet',
    'kismet-plugins',
    'airgraph-ng',
    'wifite',
    'dnsenum',
    'dnsmap',
    'ettercap-common',
    'ettercap-graphical',
    'netdiscover'
    ]

# List of packages to have SNAP install. Change if you want. You break it you buy it.
snapPackageList = [
    'chromium',
    'sqlmap',
    'john-the-ripper'
    ]

# Snaps that need --classic
# Avoid these. It's better to scrape a git for the latest and install. Zaproxy is a great example.
snapClassicPackageList =[
    #'zaproxy'
]

########################################################
# Colors
GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
NOCOLOR = '\033[m'

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

# Check for internet connection
def checkForInternet():
    try:
        check = urlopen('https://www.google.com', timeout=3.0)
        print(GREEN +'[+] Internet connection looks good!' + NOCOLOR)
    except:
        print(RED + '[-] Internet connection looks down. You will need internet for this to run (most likely). Fix and try again.' + NOCOLOR)
        exit(1)

def initNotice():
    print('[!] This script requires user input once or twice.\n\
    [!] It is not completely "Set and Forget".')
    nullInput = input('Hit Enter.')

# Get starting Disk Room
def freeSpaceStart():
    # Needs Regex Impovement with RE Search. Non Gig sized systems will break this.
    global FREE_SPACE_START_INT
    freeSpaceStart = run(['df -h /'],shell=True,capture_output=True).stdout.decode().split('G')[2].strip()
    writeToLog('[i] Gigs of Free Space on / at the Start of the build: ' + freeSpaceStart + 'G')
    FREE_SPACE_START_INT = float(freeSpaceStart)
    return(FREE_SPACE_START_INT)

def freeSpaceEnd():
    # Needs Regex Impovement with RE Search. Non Gig sized systems will break this.
    freeSpaceEnd = run(['df -h /'],shell=True,capture_output=True).stdout.decode().split('G')[2].strip()
    writeToLog('[i] Gigs of Free Space on / at the Start of the build: ' + freeSpaceEnd + 'G')
    freeSpaceEndInt = float(freeSpaceEnd)
    spaceUsed = FREE_SPACE_START_INT - freeSpaceEndInt
    writeToLog('[i] Gigs of Space used for InfoSec-Fortress Buildout: ' + str(spaceUsed) + 'G')

# Check/Inform about for unattended upgrade
def informAboutUnattendedUpgade():
    print('[!][!][!][!][!][!][!][!]\nUnattended Upgades firing while this script is running will break it.\
    \nKill or complete the upgrades if you recently booted or rebooted. Then continue.\
    \nIT MAY REQUIRE A REBOOT! If so, kill this script. Reboot. Run the updates. Run this script again.')
    nullInput = input('Hit any key to continue.')

def createFortressDir(FORTRESS_DIR):
    print('[*] Creating InfoSec Fortress Dir at:',FORTRESS_DIR)
    try:
        makedirs(FORTRESS_DIR, exist_ok=True)
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
        print('\n' + GREEN + stringToLog + NOCOLOR + '\n----------------------------------------------------------\n')
    elif '[-]' in stringToLog:
        print('\n' + RED + stringToLog + NOCOLOR + '\n----------------------------------------------------------\n')
    elif '[i]' in stringToLog + NOCOLOR:
        print('\n' + YELLOW + stringToLog + NOCOLOR + '\n----------------------------------------------------------\n')
    else:
        print('\n' + stringToLog + '\n----------------------------------------------------------\n')

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

def buildSnapClassicPackagesList():
    listOfPackagesCommand = ''
    for package in snapClassicPackageList:
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
        writeToLog('[+] REMnux Added On (downloaded and ran).')
    except Exception as e:
        writeToLog('[-] Something went wrong during the REMnux install. Error: ' + str(e))

# Install SIFT
def installSIFTPackages():
    writeToLog('[*] Finding latest SIFT Release.')
    try:
        latestLinkPage  = get('https://github.com/sans-dfir/sift-cli/releases/latest').text.splitlines()
        latestSIFTBinLine = [match for match in latestLinkPage if "sift-cli-linux" in match][4].split('"')[1]
        latestSIFTBin = search('https:.*sift-cli-linux',latestSIFTBinLine)[0]
        writeToLog('[+] latest SIFT BIN: ' + latestSIFTBin)
    except Exception as e:
        writeToLog('[-] latest SIFT Bin not found. Error: ' + str(e))
        return
    writeToLog('[*] Installing SIFT Packages.')
    try:
        run(['/usr/bin/curl -Lo /usr/local/bin/sift ' + latestSIFTBin],shell=True)
        run(['/usr/bin/chmod +x /usr/local/bin/sift'],shell=True)
        run(['/usr/local/bin/sift install --mode=packages-only'],shell=True)
        writeToLog('[+] SIFT Packages installed (downloaded and ran).')
    except Exception as e:
        writeToLog('[-] Installation of SIFT Packages had an error. Error: '+str(e))

# install base packages
def installAPTandSNAPPackages():
    print('[i] If Wireshark asks - say YES non-super users can capture packets.\n\n\
    [i] When snort asks about a monitoring interface enter lo.\n\
    [i] Setting the interface to "lo" (no quotes) sets it for local use.\n\
    [i] Set any private network for the "home" network.\n\n\
    [i] KISMET - Say YES to the sticky bit. Add your username to the Kismet Goup at the prompt.')
    nullInput = input('Hit Enter.')
    aptPackages = buildAptPackageList()
    snapPackages = buildSnapPackageList()
    snapClassicPackages = buildSnapClassicPackagesList()
    writeToLog('[*] Attempting installation of the following ATP packages: ' + aptPackages)
    try:
        run(['/usr/bin/apt install -y ' + aptPackages],shell=True)
        writeToLog('[+] APT Packages installed.')
    except Exception as e:
        writeToLog('[-] APT Packages installation failed:',str(e))
    writeToLog('[*] Attempting installation of the following Snap Packages: ' + snapPackages)
    try:
        run(['/usr/bin/snap install ' + snapPackages],shell=True)
        writeToLog('[+] Snap Packages installed.')        
    except Exception as e:
        writeToLog('[-] Snap packages installation failed:',str(e))
    if len(snapClassicPackages) == 0:
        writeToLog('[*] No snap classics to install.')
        return
    writeToLog('[*] Attempting installation of the following Snap Classic Packages: ' + snapClassicPackages)
    for package in snapClassicPackageList:
        try:
            run(['/usr/bin/snap install --classic ' + package],shell=True)
            writeToLog('[+] Snap Classic ' + package + ' installed.')
        except Exception as e:
            writeToLog('[-] Snap packages ' + package + ' failed:',str(e))

# Swap Netcats
# Change out netcat-bsd for netcat-traditional
def swapNetcat():
    writeToLog('[*] Attempting to trade out netcat-bsd for netcat-traditional')
    try:
        run(['/usr/bin/apt purge  -y netcat-openbsd'],shell=True)
        run(['/usr/bin/apt install -y netcat-traditional'],shell=True)
        writeToLog('[+] netcat-traditional installed.')
    except Exception as e:
        writeToLog('[-] Installation of netcat-traditional failed. Error: '+str(e))

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
    # Add fuzzing list for burp/SQLI (xplatform.txt)
def installWordlists():
    # Error handling using git in this way (with run) sucks.
    writeToLog('[*] Installing Wordlists to /usr/share/wordlists')
    makedirs('/usr/share/wordlists/', exist_ok=True)
    try:
        run(['/usr/bin/git clone https://github.com/3ndG4me/KaliLists.git /usr/share/wordlists/'],shell=True)
        run(['/usr/bin/rm /usr/share/wordlists/README.md'],shell=True)
        run(['/usr/bin/gunzip /usr/share/wordlists/rockyou.txt.gz'],shell=True)
        writeToLog('[+] Kali default wordlists added and unpacked.')
    except Exception as e:
        writeToLog('[-] There was an error installing Kali default wordlists. Error: ' + str(e))
    try:
        run(['/usr/bin/wget https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/xplatform.txt \
            -O /usr/share/wordlists/xplatform.txt'],shell=True)
        writeToLog('[+] Xplatform.txt SQLI Validation list added.')
    except Exception as e:
        writeToLog('[-] There was an error adding xplatform.txt. Error: ' + str(e))

#Install exploit-db
def installExploitDb():
    writeToLog('[*] Installing ExploitDB.')
    try:
        run(['/usr/bin/git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb'],shell=True)
        run(['/usr/bin/ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit'],shell=True)
        writeToLog('[+] Exploit DB Added.')
    except Exception as e:
        writeToLog('[-] There was an error installing ExploitDB. Error: ' + str(e))
    try:
        writeToLog('[*] Updating ExploitDB...')
        run(['/usr/local/bin/searchsploit -u'],shell=True)
        writeToLog('[+] Exploit DB Updated.')
    except Exception as e:
        writeToLog('[-] There was an error updating ExploitDB. Error: ' + str(e))

# elasticsearch containers?

# powershell Core
# REMnux already installs it.
#def installPosh():
#    writeToLog('[*] Installing Powershell.')
#    try:
#        run(['/usr/bin/apt-get update\
#            && /usr/bin/apt-get install -y wget apt-transport-https software-properties-common\
#            && /usr/bin/wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb\
#            && /usr/bin/dpkg -i packages-microsoft-prod.deb\
#            && /usr/bin/apt-get update\
#            && /usr/bin/add-apt-repository universe\
#            && /usr/bin/apt-get install -y powershell'],shell=True)
#        writeToLog('[+] Powershell installed.')
#    except Exception as e:
#        writeToLog('[-] There was an error installing Powershell. Error: ' + str(e))

# Install Impacket
def installImpacket():
    writeToLog('[*] Installing Impacket.')
    try:
        run(['/usr/bin/git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket'],shell=True)
        run(['/usr/bin/python3 -m pip install /opt/impacket/.'],shell=True)
        writeToLog('[+] Impacket Installed.')
    except Exception as e:
        writeToLog('[-] There was an error installing Impacket. Error: ' + str(e))

# enum4Linux
def installEnum():
    writeToLog('[*] Installing Enum4Linux.')
    try:
        run(['/usr/bin/git clone https://github.com/CiscoCXSecurity/enum4linux.git /opt/enum4linux'],shell=True)
        run(['/usr/bin/ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux.pl'],shell=True)
        writeToLog('[+] Enum4Linux Installed.')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux. Error: ' + str(e))

# enum4linux
def installEnumNG():
    writeToLog('[*] Installing Enum4Linux-ng.')
    try:
        run(['/usr/bin/git clone https://github.com/cddmp/enum4linux-ng /opt/enum4linux-ng'],shell=True)
        run(['/usr/bin/ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng.py'],shell=True)
        writeToLog('[+] Enum4Linux-ng Installed.')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux-ng. Error: ' + str(e))

# Install WebShells
def installWebShells():
    writeToLog('[*] Installing Kali\'s Webshells')
    try:
        run(['/usr/bin/git clone https://gitlab.com/kalilinux/packages/webshells.git /usr/share/webshells'],shell=True)
        writeToLog('[+] Kali\'s WebShells Cloned to /usr/share/webshells')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux. Error: ' + str(e))

# Install Windows Resources
def installWindowsResources():
    writeToLog('[*] Installing Kali\'s Windows Resources')
    try:
        run(['/usr/bin/git clone https://gitlab.com/kalilinux/packages/windows-binaries.git /usr/share/windows-resources'],shell=True)
        writeToLog('[+] Kali\'s Windows Resources Cloned to /usr/share/webshells')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux. Error: ' + str(e))

# Install Bloodhound
def installBloodhound():
    writeToLog('[*] Finding latest Blood Hound Release.')
    try:
        latestLinkPage  = get('https://github.com/BloodHoundAD/BloodHound/releases/latest').text.splitlines()
        latestBloodHoundZip = [match for match in latestLinkPage if "BloodHound-linux-x64.zip" in match][0].split('"')[1]
        writeToLog('[+] latest Blood Hound Zip at: ' + latestBloodHoundZip)
    except Exception as e:
        writeToLog('[-] latest Blood Hound Zip not found. Error: ' + str(e))
        return
    writeToLog('[*] Installing Bloodhound...')
    try:
        run(['/usr/bin/curl -Lo /tmp/bloodhound.zip https://github.com' + latestBloodHoundZip],shell=True)
        run(['/usr/bin/unzip -o /tmp/bloodhound.zip -d /opt/'],shell=True)
    except Exception as e:
        writeToLog('[-] Bloodhound not installed. Error: ' + str(e))

# Find and install latest Zaproxy
def installZaproxy():
    writeToLog('[*] Finding latest Zaproxy Release.')
    try:
        latestLinkPage  = get('https://github.com/zaproxy/zaproxy/releases/latest').text.splitlines()
        latestZapDeb = [match for match in latestLinkPage if "_all.deb" in match][0].split('"')[1]
        writeToLog('[+] latest Zaproxy Zip at: ' + latestZapDeb)
    except Exception as e:
        writeToLog('[-] latest Zaproxy Zip not found. Error: ' + str(e))
        return
    writeToLog('[*] Installing Zaproxy...')
    try:
        run(['/usr/bin/curl -Lo /tmp/zaproxy.deb ' + latestZapDeb],shell=True)
        run(['/usr/bin/dpkg -i /tmp/zaproxy.deb'],shell=True)
    except Exception as e:
        writeToLog('[-] Zaproxy not installed. Error: ' + str(e))

# display log
def displayLog():
    print('[*] The following activities were logged:\n')
    with open(LOG,'r') as log:
        allLines = log.readlines()
        for line in allLines:
            print(line.strip())

# display fortress artwork

# display message about updating ZAP and Burp after reboot
def giveUserNextSteps():
    print(GREEN + '[+]' + '-----------------------------------------------------------------------------------' + NOCOLOR)
    print(GREEN + '[+]' + '------------------------ ! Script Complete ! --------------------------------------' + NOCOLOR)
    print('\n\n[!] REBOOT the system. After Reboot you will want to run Burp, Zap and Ghidra. Each will ask you to update.\
        \n    You should update these. If they have you download a .deb file you simple run ' + GREEN + 'dpkg -i foo.deb' + NOCOLOR + '.')
    nullInput = input('Hit Enter.')

# Re-enable unattended upgrade
    #Only needed if auto kill of unattended upgrades is added

def main():
    checkIfRoot()
    checkForInternet()
    initNotice()
    informAboutUnattendedUpgade()
    createFortressDir(FORTRESS_DIR)
    startLogFile()
    freeSpaceStart()
    updateOS()
    installStarterPackages()
    installREMnux()
    installSIFTPackages()
    installAPTandSNAPPackages()
    swapNetcat()
    installMSF()
    installWordlists()
    installExploitDb()
    installImpacket()
    installEnum()
    installEnumNG()
    installWebShells()
    installWindowsResources()
    installBloodhound()
    freeSpaceEnd()
    displayLog()
    giveUserNextSteps()
    exit(0)

main()
if __name__== "__main__":
    main()