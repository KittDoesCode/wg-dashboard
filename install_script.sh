#!/bin/bash

#########################################
#
# Not really maintained, and there are a few things to do:
#   1. Prompt for the IP address.
#   2. Prompt for the default search domain.
#
#########################################

set -e

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, this script must be run as root"
	echo "Maybe try this:"
	echo "curl https://raw.githubusercontent.com/WashboardCode/wg-dashboard/master/install_script.sh | sudo bash"
	exit
fi

# i = distributor id, s = short, gives us name of the os ("Ubuntu", "Debian", ...)
if [[ "$(lsb_release -is)" == "Ubuntu" ]]; then
	# needed for add-apt-repository
	apt-get install -y software-properties-common
	# add wireguard repository to apt
	add-apt-repository -y ppa:wireguard/wireguard
	# install wireguard
	apt-get install -y wireguard
	# install linux kernel headers
	apt-get install -y linux-headers-$(uname -r)
elif [[ "$(lsb_release -is)" == "Debian" ]]; then
	if [[ "$(lsb_release -rs)" -ge "10" ]]; then
		# add unstable list
		echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
		printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
		# update repository
		apt update
		# install linux kernel headers
		apt-get install -y "linux-headers-$(uname -r)" ufw
		# install wireguard
		apt install -y wireguard
		# update again (needed because of the linux kernel headers)
		apt-get update && apt-get upgrade
	else
		echo "Sorry, your operating system is not supported"
		exit
	fi
else
	echo "Sorry, your operating system is not supported"
	exit
fi

# enable ipv4 packet forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
# install nodejs
curl https://deb.nodesource.com/setup_10.x | bash
apt-get install -y nodejs

# go into home folder
cd /opt
# delete wg-dashboard folder and wg-dashboard.tar.gz to make sure it does not exist
rm -rf wg-dashboard
rm -rf wg-dashboard.tar.gz
# download wg-dashboard latest release
curl -L https://github.com/$(wget https://github.com/WashboardCode/wg-dashboard/releases/latest -O - | egrep '/.*/.*/.*tar.gz' -o) --output wg-dashboard.tar.gz
# create directory for dashboard
mkdir -p wg-dashboard
# unzip wg-dashboard
tar -xzf wg-dashboard.tar.gz --strip-components=1 -C wg-dashboard
# delete unpacked .tar.gz
rm -f wg-dashboard.tar.gz
# go into wg-dashboard folder
cd wg-dashboard
# install node modules
npm i --production --unsafe-perm

# create service unit file
echo "[Unit]
Description=wg-dashboard service
After=network.target

[Service]
Restart=always
WorkingDirectory=/opt/wg-dashboard
ExecStart=/usr/bin/node /opt/wg-dashboard/src/server.js

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/wg-dashboard.service

# reload systemd unit files
systemctl daemon-reload
# start wg-dashboard service on reboot
systemctl enable wg-dashboard
# start wg-dashboard service
systemctl start wg-dashboard

# enable port 22 in firewall for ssh
ufw allow 22
# enable firewall
ufw --force enable
# enable port 58210 in firewall for wireguard
ufw allow 58210
# enable port 53 in firewall for dns
ufw allow in on wg0 to any port 53
# Allow access to web server
ufw allow from any to any port 10000 proto tcp

# Install go-dnsmasq
cd /usr/local/sbin
if [[ "$(lsb_release -is)" == "Ubuntu" ]]; then
	# download coredns
	curl -L https://github.com/janeczku/go-dnsmasq/releases/download/1.0.7/go-dnsmasq_linux-amd64 --output go-dnsmasq
elif [[ "$(lsb_release -is)" == "Debian" ]]; then
	# download coredns
	curl -L https://github.com/janeczku/go-dnsmasq/releases/download/1.0.7/go-dnsmasq_linux-amd64 --output go-dnsmasq
fi

# change permissions
chmod 744 /usr/local/sbin/go-dnsmasq

# write autostart config
echo "
[Unit]
Description=Go-dnsmasq DNS Server
Documentation=https://github.com/janeczku/go-dnsmasq
After=network.target

[Service]
LimitNOFILE=8192
ExecStart=/usr/local/sbin/go-dnsmasq \
    --listen 0.0.0.0 \
    --search-domains [ad.domain] \
    --enable-search \
    --nameservers IP.AD.DR.ESS
Restart=on-failure

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/go-dnsmasq.service

# disable systemd-resolved from startup
systemctl disable systemd-resolved
# stop systemd-resolved service
systemctl stop systemd-resolved
# enable go-dnsmasq on system start
systemctl enable go-dnsmasq
# start go-dnsmasq
systemctl start go-dnsmasq

# ** To be completed **
# Requires prompting for hostname, domain, etc.
# Recommendations (for now)
#echo "We currently recommend allowing port 80 (http) into this server to get a Let's Encrypt TLS certificate"
echo "Security audits have not been performed on the dashboard, so we don't recommend exposing it to the Internet"
# install nginx
#apt install nginx
# install site config
#
# install acme
#curl https://get.acme.sh | sh
# get certificate.

echo ""
echo ""
echo "=========================================================================="
echo ""
echo "> Done! WireGuard and wg-dashboard have been successfully installed"
#echo "> You can now connect to the dashboard via ssh tunnel by visiting:"
#echo ""
#echo -e "\t\thttp://localhost:3000"
#echo ""
#echo "> You can open an ssh tunnel from your local machine with this command:"
#echo ""
#echo -e "\t\tssh -L 3000:localhost:3000 <your_vps_user>@<your_vps_ip>"
#echo ""
#echo "> Please save this command for later, as you will need it to access the dashboard"
echo ""
echo "=========================================================================="
echo ""
echo ""