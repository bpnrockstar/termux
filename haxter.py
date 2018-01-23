import os
import sys
import time
from time import sleep as timeout
HAXTER = '''
 _       _
| |__ (_)_ __ (_)_ __
| '_ \| | '_ \| | '_ \
| |_) | | |_) | | | | |
|_.__/|_| .__/|_|_| |_|
        |_|
'''

tomenu_banner = '\n  [B] Back to main menu\n  [E] Exit the Lazymux\n'

def restart_program():
    python = sys.executable
    os.execl(python, python, *sys.argv)
    curdir = os.getcwd()


def backtomenu_option():
    print backtomenu_banner
    backtomenu = raw_input('HAXTER > ')
    if backtomenu == 'B':
        restart_program()
    elif backtomenu == 'E':
        sys.exit()
    else:
        print '\nERROR: Wrong Input'
        time.sleep(2)
        restart_program()


def banner():
    print HAXTER


def nmap():
    print '###### Installing Nmap'
    os.system('apt update && apt upgrade')
    os.system('apt install nmap')
    print '###### Done'
    print "###### Type 'nmap' to start."
    backtomenu_option()


def red_hawk():
    print '###### Installing RED HAWK'
    os.system('apt update && apt upgrade')
    os.system('apt install git php')
    os.system('git clone https://github.com/Tuhinshubhra/RED_HAWK')
    os.system('mv RED_HAWK ~')
    print '###### Done'
    backtomenu_option()


def dtect():
    print '###### Installing D-Tect'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/shawarkhanethicalhacker/D-TECT')
    os.system('mv D-TECT ~')
    print '###### Done'
    backtomenu_option()


def sqlmap():
    print '###### Installing sqlmap'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('git clone https://github.com/sqlmapproject/sqlmap')
    os.system('mv sqlmap ~')
    print '###### Done'
    backtomenu_option()


def infoga():
    print '###### Installing Infoga'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('pip2 install requests urllib3 urlparse')
    os.system('git clone https://github.com/m4ll0k/Infoga')
    os.system('mv Infoga ~')
    print '###### Done'
    backtomenu_option()


def reconDog():
    print '###### Installing ReconDog'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/UltimateHackers/ReconDog')
    os.system('mv ReconDog ~')
    print '###### Done'
    backtomenu_option()


def androZenmap():
    print '###### Installing AndroZenmap'
    os.system('apt update && apt upgrade')
    os.system('apt install nmap curl')
    os.system('curl -O http://override.waper.co/files/androzenmap.txt')
    os.system('mkdir ~/AndroZenmap')
    os.system('mv androzenmap.txt ~/AndroZenmap/androzenmap.sh')
    print '###### Done'
    backtomenu_option()


def sqlmate():
    print '###### Installing sqlmate'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('pip2 install mechanize bs4 HTMLparser argparse requests urlparse2')
    os.system('git clone https://github.com/UltimateHackers/sqlmate')
    os.system('mv sqlmate ~')
    print '###### Done'
    backtomenu_option()


def astraNmap():
    print '###### Installing AstraNmap'
    os.system('apt update && apt upgrade')
    os.system('apt install git nmap')
    os.system('git clone https://github.com/Gameye98/AstraNmap')
    os.system('mv AstraNmap ~')
    print '###### Done'
    backtomenu_option()


def wtf():
    print '###### Installing WTF'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('pip2 bs4 requests HTMLParser urlparse mechanize argparse')
    os.system('git clone https://github.com/Xi4u7/wtf')
    os.system('mv wtf ~')
    print '###### Done'
    backtomenu_option()


def easyMap():
    print '###### Installing Easymap'
    os.system('apt update && apt upgrade')
    os.system('apt install php git')
    os.system('git clone https://github.com/Cvar1984/Easymap')
    os.system('mv Easymap ~')
    os.system('cd ~/Easymap && sh install.sh')
    print '###### Done'
    backtomenu_option()


def xd3v():
    print '###### Installing XD3v'
    os.system('apt update && apt upgrade')
    os.system('apt install curl')
    os.system('curl -k -O https://gist.github.com/Gameye98/92035588bd0228df6fb7fa77a5f26bc2/raw/f8e73cd3d9f2a72bd536087bb6ba7bc8baef7d1d/xd3v.sh')
    os.system('mv xd3v.sh ~/../usr/bin/xd3v && chmod +x ~/../usr/bin/xd3v')
    print '###### Done'
    print "###### Type 'xd3v' to start."
    backtomenu_option()


def crips():
    print '###### Installing Crips'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2 openssl curl libcurl wget')
    os.system('git clone https://github.com/Manisso/Crips')
    os.system('mv Crips ~')
    print '###### Done'
    backtomenu_option()


def sir():
    print '###### Installing SIR'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('pip2 install bs4 urllib2')
    os.system('git clone https://github.com/AeonDave/sir.git')
    os.system('mv sir ~')
    print '###### Done'
    backtomenu_option()


def xshell():
    print '###### Installing Xshell'
    os.system('apt update && apt upgrade')
    os.system('apt install lynx python2 figlet ruby php nano w3m')
    os.system('git clone https://github.com/Ubaii/Xshell')
    os.system('mv Xshell ~')
    print '###### Done'
    backtomenu_option()


def evilURL():
    print '###### Installing EvilURL'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2 python3')
    os.system('git clone https://github.com/UndeadSec/EvilURL')
    os.system('mv EvilURL ~')
    print '###### Done'
    backtomenu_option()


def striker():
    print '###### Installing Striker'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('git clone https://github.com/UltimateHackers/Striker')
    os.system('mv Striker ~')
    os.system('cd ~/Striker && pip2 install -r requirements.txt')
    print '###### Done'
    backtomenu_option()


def dsss():
    print '###### Installing DSSS'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/stamparm/DSSS')
    os.system('mv DSSS ~')
    print '###### Done'
    backtomenu_option()


def sqliv():
    print '###### Installing SQLiv'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/Hadesy2k/sqliv')
    os.system('mv sqliv ~')
    print '###### Done'
    backtomenu_option()


def sqlscan():
    print '###### Installing sqlscan'
    os.system('apt update && apt upgrade')
    os.system('apt install git php')
    os.system('git clone http://www.github.com/Cvar1984/sqlscan')
    os.system('mv sqlscan ~')
    print '###### Done'
    backtomenu_option()


def wordpreSScan():
    print '###### Installing Wordpresscan'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 python2-dev clang libxml2-dev libxml2-utils libxslt-dev')
    os.system('git clone https://github.com/swisskyrepo/Wordpresscan')
    os.system('mv Wordpresscan ~')
    os.system('cd ~/Wordpresscan && pip2 install -r requirements.txt')
    print '###### Done'
    backtomenu_option()


def wpscan():
    print '###### Installing WPScan'
    os.system('apt update && apt upgrade')
    os.system('apt install git ruby curl')
    os.system('git clone https://github.com/wpscanteam/wpscan')
    os.system('mv wpscan ~ && cd ~/wpscan')
    os.system('gem install bundle && bundle config build.nokogiri --use-system-libraries && bundle install && ruby wpscan.rb --update')
    print '###### Done'
    backtomenu_option()


def wordpresscan():
    print '###### Installing wordpresscan(2)'
    os.system('apt update && apt upgrade')
    os.system('apt install nmap figlet git')
    os.system('git clone https://github.com/silverhat007/termux-wordpresscan')
    os.system('cd termux-wordpresscan && chmod +x * && sh install.sh')
    os.system('mv termux-wordpresscan ~')
    print '###### Done'
    print "###### Type 'wordpresscan' to start."
    backtomenu_option()


def routersploit():
    print '###### Installing Routersploit'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('pip2 install requests')
    os.system('git clone https://github.com/reverse-shell/routersploit')
    os.system('mv routersploit ~;cd ~/routersploit;pip2 install -r requirements.txt;termux-fix-shebang rsf.py')
    print '###### Done'
    backtomenu_option()


def torshammer():
    print '###### Installing Torshammer'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/dotfighter/torshammer')
    os.system('mv torshammer ~')
    print '###### Done'
    backtomenu_option()


def slowloris():
    print '###### Installing Slowloris'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/gkbrk/slowloris')
    os.system('mv slowloris ~')
    print '###### Done'
    backtomenu_option()


def fl00d12():
    print '###### Installing Fl00d & Fl00d2'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 wget')
    os.system('mkdir ~/fl00d')
    os.system('wget http://override.waper.co/files/fl00d.apk')
    os.system('wget http://override.waper.co/files/fl00d2.apk')
    os.system('mv fl00d.apk ~/fl00d/fl00d.py;mv fl00d2.apk ~/fl00d/fl00d2.py')
    print '###### Done'
    backtomenu_option()


def goldeneye():
    print '###### Installing GoldenEye'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('git clone https://github.com/jseidl/GoldenEye')
    os.system('mv GoldenEye ~')
    print '###### Done'
    backtomenu_option()


def xerxes():
    print '###### Installing Xerxes'
    os.system('apt update && apt upgrade')
    os.system('apt install git')
    os.system('apt install clang')
    os.system('git clone https://github.com/zanyarjamal/xerxes')
    os.system('mv xerxes ~')
    os.system('cd ~/xerxes && clang xerxes.c -o xerxes')
    print '###### Done'
    backtomenu_option()


def planetwork_ddos():
    print '###### Installing Planetwork-DDOS'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('git clone https://github.com/Hydra7/Planetwork-DDOS')
    os.system('mv Planetwork-DDOS ~')
    print '###### Done'
    backtomenu_option()


def hydra():
    print '###### Installing Hydra'
    os.system('apt update && apt upgrade')
    os.system('apt install hydra')
    print '###### Done'
    backtomenu_option()


def black_hydra():
    print '###### Installing Black Hydra'
    os.system('apt update && apt upgrade')
    os.system('apt install hydra git python2')
    os.system('git clone https://github.com/Gameye98/Black-Hydra')
    os.system('mv Black-Hydra ~')
    print '###### Done'
    backtomenu_option()


def cupp():
    print '###### Installing Cupp'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/Mebus/cupp')
    os.system('mv cupp ~')
    print '###### Done'
    backtomenu_option()


def leethash():
    print '###### Installing 1337Hash'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('git clone https://github.com/Gameye98/1337Hash')
    os.system('mv 1337Hash ~')
    print '###### Done'
    backtomenu_option()


def hash_buster():
    print '###### Installing Hash-Buster'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/UltimateHackers/Hash-Buster')
    os.system('mv Hash-Buster ~')
    print '###### Done'
    backtomenu_option()


def instaHack():
    print '###### Installing InstaHack'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('pip2 install requests')
    os.system('git clone https://github.com/avramit/instahack')
    os.system('mv instahack ~')
    print '###### Done'
    backtomenu_option()


def indonesian_wordlist():
    print '###### Installing indonesian-wordlist'
    os.system('apt update && apt upgrade')
    os.system('apt install git')
    os.system('git clone https://github.com/geovedi/indonesian-wordlist')
    os.system('mv indonesian-wordlist ~')
    print '###### Done'
    backtomenu_option()


def facebook_bruteForce():
    print '###### Installing Facebook Brute Force'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 wget')
    os.system('pip2 install mechanize')
    os.system('mkdir ~/facebook-brute')
    os.system('wget http://override.waper.co/files/facebook.apk')
    os.system('wget http://override.waper.co/files/password.apk')
    os.system('mv facebook.apk ~/facebook-brute/facebook.py;mv password.apk ~/facebook-brute/password.txt')
    print '###### Done'
    backtomenu_option()


def facebook_BruteForce():
    print '###### Installing Facebook Brute Force 2'
    os.system('apt update && apt upgrade')
    os.system('apt install wget python2')
    os.system('pip2 install mechanize')
    os.system('wget http://override.waper.co/files/facebook2.apk')
    os.system('wget http://override.waper.co/files/password.apk')
    os.system('mkdir ~/facebook-brute-2')
    os.system('mv facebook2.apk ~/facebook-brute-2/facebook2.py && mv password.apk ~/facebook-brute-2/password.txt')
    print '###### Done'
    backtomenu_option()


def fbBrute():
    print '###### Installing Facebook Brute Force 3'
    os.system('apt update && apt upgrade')
    os.system('apt install wget python2')
    os.system('pip2 install mechanize')
    os.system('wget http://override.waper.co/files/facebook3.apk')
    os.system('wget http://override.waper.co/files/password.apk')
    os.system('mkdir ~/facebook-brute-3')
    os.system('mv facebook3.apk ~/facebook-brute-3/facebook3.py && mv password.apk ~/facebook-brute-3/password.txt')
    print '###### Done'
    backtomenu_option()


def webdav():
    print '###### Installing Webdav'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 openssl curl libcurl')
    os.system('pip2 install urllib3 chardet certifi idna requests')
    os.system('mkdir ~/webdav')
    os.system('curl -k -O http://override.waper.co/files/webdav.txt;mv webdav.txt ~/webdav/webdav.py')
    print '###### Done'
    backtomenu_option()


def xGans():
    print '###### Installing xGans'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 curl')
    os.system('mkdir ~/xGans')
    os.system('curl -O http://override.waper.co/files/xgans.txt')
    os.system('mv xgans.txt ~/xGans/xgans.py')
    print '###### Done'
    backtomenu_option()


def webmassploit():
    print '###### Installing Webdav Mass Exploiter'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 openssl curl libcurl')
    os.system('pip2 install requests')
    os.system('curl -k -O https://pastebin.com/raw/K1VYVHxX && mv K1VYVHxX webdav.py')
    os.system('mkdir ~/webdav-mass-exploit && mv webdav.py ~/webdav-mass-exploit')
    print '###### Done'
    backtomenu_option()


def wpsploit():
    print '###### Installing WPSploit'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone git clone https://github.com/m4ll0k/wpsploit')
    os.system('mv wpsploit ~')
    print '###### Done'
    backtomenu_option()


def sqldump():
    print '###### Installing sqldump'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 curl')
    os.system('pip2 install google')
    os.system('curl -k -O https://gist.githubusercontent.com/Gameye98/76076c9a282a6f32749894d5368024a6/raw/6f9e754f2f81ab2b8efda30603dc8306c65bd651/sqldump.py')
    os.system('mkdir ~/sqldump && chmod +x sqldump.py && mv sqldump.py ~/sqldump')
    print '###### Done'
    backtomenu_option()


def websploit():
    print '###### Installing Websploit'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('pip2 install scapy')
    os.system('git clone https://github.com/The404Hacking/websploit')
    os.system('mv websploit ~')
    print '###### Done'
    backtomenu_option()


def sqlokmed():
    print '###### Installing sqlokmed'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('pip2 install urllib2')
    os.system('git clone https://github.com/Anb3rSecID/sqlokmed')
    os.system('mv sqlokmed ~')
    print '###### Done'
    backtomenu_option()


def zones():
    print '######'
    os.system('apt update && apt upgrade')
    os.system('apt install git php')
    os.system('git clone https://github.com/Cvar1984/zones')
    os.system('mv zones ~')
    print '######'
    backtomenu_option()


def metasploit():
    print '###### Installing Metasploit'
    os.system('apt update && apt upgrade')
    os.system('apt install git wget curl')
    os.system('wget https://gist.githubusercontent.com/Gameye98/d31055c2d71f2fa5b1fe8c7e691b998c/raw/09e43daceac3027a1458ba43521d9c6c9795d2cb/msfinstall.sh')
    os.system('mv msfinstall.sh ~;cd ~;sh msfinstall.sh')
    print '###### Done'
    print "###### Type 'msfconsole' to start."
    backtomenu_option()


def commix():
    print '###### Installing Commix'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/commixproject/commix')
    os.system('mv commix ~')
    print '###### Done'
    backtomenu_option()


def brutal():
    print '###### Installing Brutal'
    os.system('apt update && apt upgrade')
    os.system('apt install git')
    os.system('git clone https://github.com/Screetsec/Brutal')
    os.system('mv Brutal ~')
    print '###### Done'
    backtomenu_option()


def a_rat():
    print '###### Installing A-Rat'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/Xi4u7/A-Rat')
    os.system('mv A-Rat ~')
    print '###### Done'
    backtomenu_option()


def knockmail():
    print '###### Installing KnockMail'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('pip2 install validate_email pyDNS')
    os.system('git clone https://github.com/4w4k3/KnockMail')
    os.system('mv KnockMail ~')
    print '###### Done'
    backtomenu_option()


def spammer_grab():
    print '###### Installing Spammer-Grab'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git && pip2 install requests')
    os.system('git clone https://github.com/p4kl0nc4t/spammer-grab')
    os.system('mv spammer-grab ~')
    print '###### Done'
    backtomenu_option()


def hac():
    print '###### Installing Hac'
    os.system('apt update && apt upgrade')
    os.system('apt install php git')
    os.system('git clone https://github.com/Cvar1984/Hac')
    os.system('mv Hac ~')
    print '###### Done'
    backtomenu_option()


def spammer_email():
    print '###### Installing Spammer-Email'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2 && pip2 install argparse requests')
    os.system('git clone https://github.com/p4kl0nc4t/Spammer-Email')
    os.system('mv Spammer-Email ~')
    print '###### Done'
    backtomenu_option()


def rang3r():
    print '###### Installing Rang3r'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2 && pip2 install optparse termcolor')
    os.system('git clone https://github.com/floriankunushevci/rang3r')
    os.system('mv rang3r ~')
    print '###### Done'
    backtomenu_option()


def sh33ll():
    print '###### Installing SH33LL'
    os.system('apt update && apt upgrade')
    os.system('apt install git python2')
    os.system('git clone https://github.com/LOoLzeC/SH33LL')
    os.system('mv SH33LL ~')
    print '###### Done'
    backtomenu_option()


def social():
    print '###### Installing Social-Engineering'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 perl')
    os.system('git clone https://github.com/LOoLzeC/social-engineering')
    os.system('mv social-engineering ~')
    print '###### Done'
    backtomenu_option()


def spiderbot():
    print '###### Installing SpiderBot'
    os.system('apt update && apt upgrade')
    os.system('apt install git php')
    os.system('git clone https://github.com/Cvar1984/SpiderBot')
    os.system('mv SpiderBot ~')
    print '###### Done'
    backtomenu_option()


def ngrok():
    print '###### Installing Ngrok'
    os.system('apt update && apt upgrade')
    os.system('apt install git')
    os.system('git clone https://github.com/themastersunil/ngrok')
    os.system('mv ngrok ~')
    print '###### Done'
    backtomenu_option()


def sudo():
    print '###### Installing sudo'
    os.system('apt update && apt upgrade')
    os.system('apt install ncurses-utils git')
    os.system('git clone https://github.com/st42/termux-sudo')
    os.system('mv termux-sudo ~ && cd ~/termux-sudo && chmod 777 *')
    os.system('cat sudo > /data/data/com.termux/files/usr/bin/sudo')
    os.system('chmod 700 /data/data/com.termux/files/usr/bin/sudo')
    print '###### Done'
    backtomenu_option()


def ubuntu():
    print '###### Installing Ubuntu'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git')
    os.system('git clone https://github.com/Neo-Oli/termux-ubuntu')
    os.system('mv termux-ubuntu ~ && cd ~/termux-ubuntu && bash ubuntu.sh')
    print '###### Done'
    backtomenu_option()


def fedora():
    print '###### Installing Fedora'
    os.system('apt update && apt upgrade')
    os.system('apt install wget git')
    os.system('wget https://raw.githubusercontent.com/nmilosev/termux-fedora/master/termux-fedora.sh')
    os.system('mv termux-fedora.sh ~')
    print '###### Done'
    backtomenu_option()


def nethunter():
    print '###### Installing Kali NetHunter'
    os.system('apt update && apt upgrade')
    os.system('apt install git')
    os.system('git clone https://github.com/Hax4us/Nethunter-In-Termux')
    os.system('mv Nethunter-In-Termux ~')
    print '###### Done'
    backtomenu_option()


def blackbox():
    print '###### Installing BlackBox'
    os.system('apt update && apt upgrade')
    os.system('apt install python2 git && pip2 install optparse passlib')
    os.system('git clone https://github.com/jothatron/blackbox')
    os.system('mv blackbox ~')
    print '###### Done'
    backtomenu_option()

def main():
    banner()
    print '   [01] Information Gathering'
    print '   [02] Vulnerability Scanner'
    print '   [03] Stress Testing'
    print '   [04] Password Attacks'
    print '   [05] Web Hacking'
    print '   [06] Exploitation Tools'
    print '   [07] Sniffing & Spoofing'
    print '   [08] Other\n'
    print '   [10] Exit the HAXTER\n'
    HAXTER = raw_input('HAXTER > ')
    if HAXTER == '1' or HAXTER == '01':
        print '\n    [01] Nmap'
        print '    [02] Red Hawk'
        print '    [03] D-Tect'
        print '    [04] sqlmap'
        print '    [05] Infoga'
        print '    [06] ReconDog'
        print '    [07] AndroZenmap'
        print '    [08] sqlmate'
        print '    [09] AstraNmap'
        print '    [10] WTF'
        print '    [11] Easymap'
        print '    [12] BlackBox'
        print '    [13] XD3v'
        print '    [14] Crips'
        print '    [15] SIR'
        print '    [16] EvilURL'
        print '    [17] Striker'
        print '    [18] Xshell\n'
        print '    [B] Back to main menu\n'
        infogathering = raw_input('HAXTER > ')
        if infogathering == '01' or infogathering == '1':
            nmap()
        elif infogathering == '02' or infogathering == '2':
            red_hawk()
        elif infogathering == '03' or infogathering == '3':
            dtect()
        elif infogathering == '04' or infogathering == '4':
            sqlmap()
        elif infogathering == '05' or infogathering == '5':
            infoga()
        elif infogathering == '06' or infogathering == '6':
            reconDog()
        elif infogathering == '07' or infogathering == '7':
            androZenmap()
        elif infogathering == '08' or infogathering == '8':
            sqlmate()
        elif infogathering == '09' or infogathering == '9':
            astraNmap()
        elif infogathering == '10':
            wtf()
        elif infogathering == '11':
            easyMap()
        elif infogathering == '12':
            blackbox()
        elif infogathering == '13':
            xd3v()
        elif infogathering == '14':
            crips()
        elif infogathering == '15':
            sir()
        elif infogathering == '16':
            evilURL()
        elif infogathering == '17':
            striker()
        elif infogathering == '18':
            xshell()
        elif infogathering == 'B' or infogathering == 'b':
            restart_program()
        else:
            print '\nERROR: Wrong Input please enter again'
            timeout(2)
            restart_program()
    elif HAXTER == '2' or HAXTER == '02':
        print '\n    [01] Nmap'
        print '    [02] AndroZenmap'
        print '    [03] AstraNmap'
        print '    [04] Easymap'
        print '    [05] Red Hawk'
        print '    [06] D-Tect'
        print '    [07] Damn Small SQLi Scanner'
        print '    [08] SQLiv'
        print '    [09] sqlmap'
        print '    [10] sqlscan'
        print '    [11] Wordpresscan'
        print '    [12] WPScan'
        print '    [13] sqlmate'
        print '    [14] wordpresscan'
        print '    [15] WTF'
        print '    [16] Rang3r'
        print '    [17] Striker'
        print '    [18] Routersploit'
        print '    [19] Xshell'
        print '    [20] SH33LL'
        print '    [21] BlackBox\n'
        print '    [B] Back to main menu\n'
        vulnscan = raw_input('HAXTER > ')
        if vulnscan == '01' or vulnscan == '1':
            nmap()
        elif vulnscan == '02' or vulnscan == '2':
            androZenmap()
        elif vulnscan == '03' or vulnscan == '3':
            astraNmap()
        elif vulnscan == '04' or vulnscan == '4':
            easyMap()
        elif vulnscan == '05' or vulnscan == '5':
            red_hawk()
        elif vulnscan == '06' or vulnscan == '6':
            dtect()
        elif vulnscan == '07' or vulnscan == '7':
            dsss()
        elif vulnscan == '08' or vulnscan == '8':
            sqliv()
        elif vulnscan == '09' or vulnscan == '9':
            sqlmap()
        elif vulnscan == '10':
            sqlscan()
        elif vulnscan == '11':
            wordpreSScan()
        elif vulnscan == '12':
            wpscan()
        elif vulnscan == '13':
            sqlmate()
        elif vulnscan == '14':
            wordpresscan()
        elif vulnscan == '15':
            wtf()
        elif vulnscan == '16':
            rang3r()
        elif vulnscan == '17':
            striker()
        elif vulnscan == '18':
            routersploit()
        elif vulnscan == '19':
            xshell()
        elif vulnscan == '20':
            sh33ll()
        elif vulnscan == '21':
            blackbox()
        elif vulnscan == 'B' or vulnscan == 'b':
            restart_program()
        else:
            print '\nERROR: Wrong Input enter again'
            timeout(2)
            restart_program()
    elif HAXTER == '3' or HAXTER == '03':
        print '\n    [01] Torshammer'
        print '    [02] Slowloris'
        print '    [03] Fl00d & Fl00d2'
        print '    [04] GoldenEye'
        print '    [05] Xerxes'
        print '    [06] Planetwork-DDOS'
        print '    [07] Hydra'
        print '    [08] Black Hydra'
        print '    [09] Xshell\n'
        print '    [B] Back to main menu\n'
        stresstest = raw_input('lzmx > ')
        if stresstest == '01' or stresstest == '1':
            torshammer()
        elif stresstest == '02' or stresstest == '2':
            slowloris()
        elif stresstest == '03' or stresstest == '3':
            fl00d12()
        elif stresstest == '04' or stresstest == '4':
            goldeneye()
        elif stresstest == '05' or stresstest == '5':
            xerxes()
        elif stresstest == '06' or stresstest == '6':
            planetwork_ddos()
        elif stresstest == '07' or stresstest == '7':
            hydra()
        elif stresstest == '08' or stresstest == '8':
            black_hydra()
        elif stresstest == '09' or stresstest == '9':
            xshell()
        elif stresstest == 'B' or stresstest == 'b':
            restart_program()
        else:
            print '\nERROR: Wrong Input enter again'
            timeout(2)
            restart_program()
    elif HAXTER == '4' or HAXTER == '04':
        print '\n    [01] Hydra'
        print '    [02] Facebook Brute Force'
        print '    [03] Facebook Brute Force 2'
        print '    [04] Facebook Brute Force 3'
        print '    [05] Black Hydra'
        print '    [06] Hash Buster'
        print '    [07] 1337Hash'
        print '    [08] Cupp'
        print '    [09] InstaHack'
        print '    [10] Indonesian Wordlist'
        print '    [11] Xshell'
        print '    [12] Social-Engineering'
        print '    [13] BlackBox\n'
        print '    [00] Back to main menu\n'
        passtak = raw_input('lzmx > ')
        if passtak == '01' or passtak == '1':
            hydra()
        elif passtak == '02' or passtak == '2':
            facebook_bruteForce()
        elif passtak == '03' or passtak == '3':
            facebook_BruteForce()
        elif passtak == '04' or passtak == '4':
            fbBrute()
        elif passtak == '05' or passtak == '5':
            black_hydra()
        elif passtak == '06' or passtak == '6':
            hash_buster()
        elif passtak == '07' or passtak == '7':
            leethash()
        elif passtak == '08' or passtak == '8':
            cupp()
        elif passtak == '09' or passtak == '9':
            instaHack()
        elif passtak == '10':
            indonesian_wordlist()
        elif passtak == '11':
            xshell()
        elif passtak == '12':
            social()
        elif passtak == '13':
            blackbox()
        elif passtak == '00' or passtak == '0':
            restart_program()
        else:
            print '\nERROR: Wrong Input enter again'
            timeout(2)
            restart_program()
    elif HAXTER == '5' or HAXTER == '05':
        print '\n    [01] sqlmap'
        print '    [02] Webdav'
        print '    [03] xGans'
        print '    [04] Webdav Mass Exploit'
        print '    [05] WPSploit'
        print '    [06] sqldump'
        print '    [07] Websploit'
        print '    [08] sqlmate'
        print '    [09] sqlokmed'
        print '    [10] zones'
        print '    [11] Xshell'
        print '    [12] SH33LL\n'
        print '    [00] Back to main menu\n'
        webhack = raw_input('lzmx > ')
        if webhack == '01' or webhack == '1':
            sqlmap()
        elif webhack == '02' or webhack == '2':
            webdav()
        elif webhack == '03' or webhack == '3':
            xGans()
        elif webhack == '04' or webhack == '4':
            webmassploit()
        elif webhack == '05' or webhack == '5':
            wpsploit()
        elif webhack == '06' or webhack == '6':
            sqldump()
        elif webhack == '07' or webhack == '7':
            websploit()
        elif webhack == '08' or webhack == '8':
            sqlmate()
        elif webhack == '09' or webhack == '9':
            sqlokmed()
        elif webhack == '10':
            zones()
        elif webhack == '11':
            xshell()
        elif webhack == '12':
            sh33ll()
        elif webhack == '00' or webhack == '0':
            restart_program()
        else:
            print '\nERROR: Wrong Input'
            timeout(2)
            restart_program()
    elif HAXTER == '6' or HAXTER == '06':
        print '\n    [01] Metasploit'
        print '    [02] commix'
        print '    [03] sqlmap'
        print '    [04] Brutal'
        print '    [05] A-Rat'
        print '    [06] WPSploit'
        print '    [07] Websploit'
        print '    [08] Routersploit'
        print '    [09] BlackBox\n'
        print '    [B] Back to main menu\n'
        exploitool = raw_input('lzmx > ')
        if exploitool == '01' or exploitool == '1':
            metasploit()
        elif exploitool == '02' or exploitool == '2':
            commix()
        elif exploitool == '03' or exploitool == '3':
            sqlmap()
        elif exploitool == '04' or exploitool == '4':
            brutal()
        elif exploitool == '05' or exploitool == '5':
            a_rat()
        elif exploitool == '06' or exploitool == '6':
            wpsploit()
        elif exploitool == '07' or exploitool == '7':
            websploit()
        elif exploitool == '08' or exploitool == '8':
            routersploit()
        elif exploitool == '09' or exploitool == '9':
            blackbox()
        elif exploitool == 'B' or exploitool == 'b':
            restart_program()
        else:
            print '\nERROR: Wrong Input'
            timeout(2)
            restart_program()
    elif HAXTER == '7' or HAXTER == '07':
        print '\n    [01] KnockMail'
        print '    [02] Spammer-Grab'
        print '    [03] Hac'
        print '    [04] Spammer-Email\n'
        print '    [B] Back to main menu\n'
        sspoof = raw_input('lzmx > ')
        if sspoof == '01' or sspoof == '1':
            knockmail()
        elif sspoof == '02' or sspoof == '2':
            spammer_grab()
        elif sspoof == '03' or sspoof == '3':
            hac()
        elif sspoof == '04' or sspoof == '4':
            spammer_email()
        elif sspoof == 'B' or sspoof == 'b':
            restart_program()
        else:
            print '\nERROR: Wrong Input'
            timeout(2)
            restart_program()
    elif HAXTER == '8' or HAXTER == '08':
        print '\n    [01] SpiderBot'
        print '    [02] Ngrok'
        print '    [03] Sudo'
        print '    [04] Ubuntu'
        print '    [05] Fedora'
        print '    [06] Kali Nethunter\n'
        print '    [B] Back to main menu\n'
        moretool = raw_input('lzmx > ')
        if moretool == '01' or moretool == '1':
            spiderbot()
        elif moretool == '02' or moretool == '2':
            ngrok()
        elif moretool == '03' or moretool == '3':
            sudo()
        elif moretool == '04' or moretool == '4':
            ubuntu()
        elif moretool == '05' or moretool == '5':
            fedora()
        elif moretool == '06' or moretool == '6':
            nethunter()
        elif moretool == 'B' or moretool == 'b':
            restart_program()
        else:
            print '\nERROR: Wrong Input'
            timeout(2)
            restart_program()
    elif HAXTER == '10':
        sys.exit()
    else:
        print '\nERROR: Wrong Input'
        timeout(2)
        restart_program()


if __name__ == '__main__':
    main()