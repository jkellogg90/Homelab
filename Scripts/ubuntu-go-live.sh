#!/bin/bash
#Go live script for Ubuntu 18.04 server. 
#Updates the system, configures the hostname, timezone, NTP conf, disables IPv6.
#Install and configure IPtables to default deny, OpenSSH w/ keybased authentication + Duo 2FA in failclose
#Install and configure security stack (Zabbix, OSSEC, and Splunk Forwarder)
#Configures auto update cronjob

clear

if [ "$EUID" -ne 0 ]
then echo "Run as root. Exiting."
exit
fi


#Update variables as needed. Needed for FW rules and config files.
HOSTNAME="V-UBNT-TEST"
ZABBIXIP=""
ZABBIXMAC=""
JUMPBOX=""
JUMPBOXMAC=""
OSSECIP=""
SPLUNKIP=""
USER=""
DIR="/root/golive"

#Download and install security stack
OSSEC="https://github.com/ossec/ossec-hids/archive/3.2.0.tar.gz"
SPLUNKFORWARDER="https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=8.0.2&product=universalforwarder&filename=splunkforwarder-8.0.2-a7f645ddaf91-linux-2.6-amd64.deb&wget=true"
ZABBIX="https://repo.zabbix.com/zabbix/4.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.0-3+bionic_all.deb"
DUO="https://dl.duosecurity.com/duo_unix-latest.tar.gz"

echo -e "Update variables before continuing\n"
echo "Hostname will be set to: $HOSTNAME"
echo "Zabbix IP Address: $ZABBIXIP"
echo "Zabbix MAC Address: $ZABBIXMAC"
echo "Jumpbox IP Address: $JUMPBOX"
echo "Jumpbox MAC Address: $JUMPBOXMAC"
echo "OSSEC IP Address: $OSSECIP"
echo "Splunk IP Address: $SPLUNKIP"
echo "User account: $USER"

echo "OSSEC Download URL: $OSSEC"
echo "Splunk Forwarder URL: $SPLUNKFORWARDER"
echo "DUO 2FA URL: $DUO\n"

echo -n "Continue? (y/n)? "
read answer

if [ "$answer" != "${answer#[Yy]}" ] ;then
echo "Continuing"
else
echo "Exiting"
exit 1
fi

echo -e "Set Root Password"
passwd root

echo -e "Set $USER Password"
passwd $USER

echo -e "Installing OpenSSH\n"
apt install openssh-server -y
systemctl enable ssh

echo -e "Setting hostname to $HOSTNAME\n"
hostnamectl set-hostname --static $HOSTNAME

if [ -e "/etc/cloud/cloud.cfg" ]; then
echo -e "Modifying /etc/cloud/cloud.cfg file to preserve hostname\n"
sed -i -e 's/preserve_hostname: false/preserve_hostname: true/g' /etc/cloud/cloud.cfg
else
echo -e "/etc/cloud/cloud.cfg does not exist. Skipping."
fi

echo -e "Setting timezone to EST\n"
timedatectl set-timezone America/New_York

echo -e "Updating system"
sudo apt-get update
DEBIAN_FRONTEND=noninteractive sudo apt-get upgrade -y
DEBIAN_FRONTEND=noninteractive sudo apt dist-upgrade -y
DEBIAN_FRONTEND=noninteractive sudo apt-autoremove -y

echo -e "Configuring system for autoupdate via cronjob\n"
(crontab -l 2>/dev/null; echo "0 4 * * * /root/update.sh >> /root/update.log") | crontab -
(crontab -l 2>/dev/null; echo "0 5 * * 7 reboot") | crontab -

echo '#!/bin/bash' > /root/update.sh
echo "sudo apt-get update" >> /root/update.sh
echo "sudo apt-get upgrade -y" >> /root/update.sh
echo "sudo apt-autoremove -y" >> /root/update.sh

chmod 700 /root/update.sh ; chown root:root /root/update.sh
touch /root/update.log ; chmod 600 /root/update.log ; chown root:root /root/update.log

echo -e "Installing iptables persistent\n"
sudo apt install iptables-persistent -y

echo -e "Configuring iptables to default DENY\n"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT -p tcp -s $JUMPBOX --dport 22 -m mac --mac-source $JUMPBOXMAC -j ACCEPT
iptables -I INPUT -p tcp --dport 10050 -s $ZABBIXIP -m mac --mac-source $ZABBIXMAC -j ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables-save > /etc/iptables/rules.v4

#Deny IPv6
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -F
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables-save > /etc/iptables/rules.v6

echo -e "Disabling IPv6\n"
echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.d/60-ipv6-disable.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/60-ipv6-disable.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.d/60-ipv6-disable.conf
service procps restart

echo -e "Installing NTP client\n"
sudo apt install ntp -y
cat /etc/ntp.conf | grep -v "pool \|server " > temp
echo "server time1.google.com" >> temp
echo "server time2.google.com" >> temp
echo "server time3.google.com" >> temp
echo "server time4.google.com" >> temp
mv temp /etc/ntp.conf
systemctl enable ntp
service ntp restart

echo -e "Installing Duo 2FA\n"
sudo apt-get install libssl-dev libpam-dev make gcc -y
mkdir $DIR ; cd $DIR
wget $DUO
tar zxf duo_unix-latest.tar.gz -C $DIR

DUODIR=$(ls | grep -i "duo_unix-" | grep -v ".tar\|.gz")
cd $DUODIR
./configure --with-pam --prefix=/usr && make && sudo make install

echo -e "Configuring /etc/duo/pam_duo.conf\n"
read -p 'Enter Duo Integration Key: ' ikey
read -p 'Enter Duo Secret Key: ' skey
read -p 'Enter Duo Host: ' host

sed -i -e "s/ikey = /ikey = $ikey/g" /etc/duo/pam_duo.conf
sed -i -e "s/skey = /skey = $skey/g" /etc/duo/pam_duo.conf
sed -i -e "s/host = /host = $host/g" /etc/duo/pam_duo.conf

sed -i -e "s/failmode = safe/failmode = secure/g" /etc/duo/pam_duo.conf
echo "autopush = yes" >> /etc/duo/pam_duo.conf

echo -e "Configuring SSH config\n"
sed -i 's/#\?\(PubkeyAuthentication\s*\).*$/\1 yes/' /etc/ssh/sshd_config
sed -i 's/#\?\(PermitEmptyPasswords\s*\).*$/\1 no/' /etc/ssh/sshd_config
sed -i 's/#\?\(PasswordAuthentication\s*\).*$/\1 no/' /etc/ssh/sshd_config
sed -i 's/#\?\(UsePAM\s*\).*$/\1 yes/' /etc/ssh/sshd_config
sed -i 's/#\?\(UseDNS\s*\).*$/\1 no/' /etc/ssh/sshd_config
sed -i 's/#\?\(ChallengeResponseAuthentication\s*\).*$/\1 yes/' /etc/ssh/sshd_config
echo "AuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config
sed -i 's/#\?\(AuthenticationMethods\s*\).*$/\1 publickey,keyboard-interactive/' /etc/ssh/sshd_config

PAMDUO=$(find / -iname pam_duo.so | grep -i "/lib/security/pam_duo\|/lib64/security/pam_duo")

sed -i -e 's/@include common-auth/#@include common-auth/g' /etc/pam.d/sshd
echo "auth [success=1 default=ignore] $PAMDUO" >> /etc/pam.d/sshd
echo "auth requisite pam_deny.so" >> /etc/pam.d/sshd
echo "auth required pam_permit.so" >> /etc/pam.d/sshd

echo -e "Creating Authorized_Keys file\n"
mkdir /home/$USER/.ssh/
touch /home/$USER/.ssh/authorized_keys
chown $USER:$USER /home/$USER/.ssh
chmod 700 /home/$USER/.ssh
chmod 644 /home/$USER/.ssh/authorized_keys

read -p 'Enter SSH Public Key: ' pubkey
echo $pubkey >> /home/$USER/.ssh/authorized_keys

service sshd restart

echo -e "Installing Zabbix\n"
cd $DIR
wget $ZABBIX
sudo dpkg -i zabbix-release_4.0-3+bionic_all.deb

sudo apt-get update
sudo apt-get install zabbix-agent -y

sed -i -e "s/Server=127.0.0.1/Server=$ZABBIXIP/g" /etc/zabbix/zabbix_agentd.conf
sed -i -e "s/ServerActive=127.0.0.1/ServerActive=$ZABBIXIP/g" /etc/zabbix/zabbix_agentd.conf

systemctl enable zabbix-agent
systemctl restart zabbix-agent

echo -e "Installing OSSEC Agent:\n"
sudo apt-get install libz-dev gcc make -y
wget $OSSEC
tar xvf 3.2.0.tar.gz -C $DIR

OSSECDIR=$(ls | grep -i "ossec-hids" | grep -v ".tar\|.gz")
cd $OSSECDIR

cp etc/preloaded-vars.conf.example etc/preloaded-vars.conf
echo "USER_NO_STOP="y"" >> etc/preloaded-vars.conf
echo "USER_INSTALL_TYPE="agent"" >> etc/preloaded-vars.conf
echo "USER_LANGUAGE="en"" >> etc/preloaded-vars.conf
echo "USER_DIR="/var/ossec"" >> etc/preloaded-vars.conf
echo "USER_ENABLE_ACTIVE_RESPONSE="y"" >> etc/preloaded-vars.conf
echo "USER_ENABLE_SYSCHECK="y"" >> etc/preloaded-vars.conf
echo "USER_ENABLE_ROOTCHECK="y"" >> etc/preloaded-vars.conf
echo "USER_UPDATE_RULES="y"" >> etc/preloaded-vars.conf
echo "USER_AGENT_SERVER_IP="$OSSECIP"" >> etc/preloaded-vars.conf
echo "USER_ENABLE_FIREWALL_RESPONSE="y"" >> etc/preloaded-vars.conf
./install.sh

mv $OSSECDIR/etc/rules /var/ossec
chown -R root:ossec /var/ossec/rules/
chmod -R 640 /var/ossec/rules

wget

read -p 'Enter OSSEC Authentication Key from Manager: ' key
/var/ossec/bin/manage_agents -n $HOSTNAME -i $key

#Need OSSEC rules,config, and key from OSSEC server
/var/ossec/bin/ossec-control restart

echo -e "Installing Splunk Forwarder:\n"
cd $DIR
wget -O splunkforwarder-8.0.2-a7f645ddaf91-linux-2.6-amd64.deb "$SPLUNKFORWARDER"
dpkg -i splunkforwarder-8.0.2-a7f645ddaf91-linux-2.6-amd64.deb

PASSWORD=$(openssl rand -base64 32 | tr -dc '[:alnum:]\n\r')

/opt/splunkforwarder/bin/splunk enable boot-start --accept-license --no-prompt
/opt/splunkforwarder/bin/splunk add forward-server $SPLUNKIP:9997
/opt/splunkforwarder/bin/splunk stop

/opt/splunkforwarder/bin/splunk clean userdata -f

#Create Splunk User Manually
touch /opt/splunkforwarder/etc/system/local/user-seed.conf
echo "[user_info]" >> /opt/splunkforwarder/etc/system/local/user-seed.conf
echo "USERNAME = splunkuser" >> /opt/splunkforwarder/etc/system/local/user-seed.conf
echo "PASSWORD = $PASSWORD" >> /opt/splunkforwarder/etc/system/local/user-seed.conf

echo "[monitor:///var/log/]" > /opt/splunkforwarder/etc/system/local/inputs.conf
echo "index = linux" >> /opt/splunkforwarder/etc/system/local/inputs.conf
echo "disabled = false" >> /opt/splunkforwarder/etc/system/local/inputs.conf
echo "blacklist = (nagios|puppetdb|audit|^sa|proserver|foreman|\.bak$)" >> /opt/splunkforwarder/etc/system/local/inputs.conf

echo "[monitor:///var/log/syslog]" >> /opt/splunkforwarder/etc/system/local/inputs.conf
echo "disabled = false" >> /opt/splunkforwarder/etc/system/local/inputs.conf
echo "sourcetype = cmdhistory" >> /opt/splunkforwarder/etc/system/local/inputs.conf

/opt/splunkforwarder/bin/splunk start

sleep 10s

echo -e "Are services running?\n"
ZABBIXSVC=$(service zabbix-agent status | grep Active | awk '{print $2}')
OSSECSVC=$(/var/ossec/bin/ossec-control status)
SPLUNKSVC=$(sudo /opt/splunkforwarder/bin/splunk status | grep splunkd)
SSHSVC=$(service sshd status| grep Active | awk '{print $2}')

echo "Zabbix: $ZABBIXSVC"
echo "OSSEC: $OSSECSVC"
echo "SSHD: $SSHSVC"
echo -e "SPLUNK: $SPLUNKSVC\n"

echo -e "NTP servers:"
ntpq -p

echo -e "\nFW rules:\n"
iptables -nvL INPUT
echo ""
ip6tables -nvL INPUT

echo -e "\nPost-setup Instructions:\n"
echo "1. Register host in Zabbix console"
echo "2. Validate OSSEC and System logs are being sent to the SIEM"
echo "3. Validate SSH authentication w/ Duo works"
echo "4. Disable any additional services if listening (netstat -antpu)"
echo "5. Enable CLI logging https://www.patrick-bareiss.com/monitor-bash-commands-on-centos-with-splunk/"
echo -e "6. Reboot and run updates again\n"

echo -e "Splunk PW:" "$PASSWORD"\n
