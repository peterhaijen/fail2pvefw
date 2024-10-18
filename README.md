# fail2pvefw
Fail2Ban action to add banned IPs to an IPSet on a Proxmox host

## Description

This is an extension for Fail2Ban, which makes it possible to have an action that adds a banned IP address to
an IPSet defined at datacenter level in Proxmox. This IPSet can then be used in the firewall configuration of
any node, VM or CT to block bad IPs.

This has been tested on Proxmox VE v8.2.7 and a Debian 12 VM with Fail2Ban v1.0.2-2.

## Installation

### On the Proxmox server


No additional software is required on the Proxmox server, because the script uses the existing [Proxmox VE API
](https://pve.proxmox.com/wiki/Proxmox_VE_API) on the host.

What is required is an API token with the necessary privileges.

#### Create a new API token

Go to Datacenter => Permissions, then:

- Create a new Role, `Fail2BanAdmin`, and allow the privileges `Sys.Audit` and `Sys.Modify`
- Create a new Group, `fail2ban`
- Add Group permissions: Path `/`, Group `fail2ban`, Role `Fail2BanAdmin`
- Create a new user `fail2ban@pve` and make this user a member of the group `fail2ban`. The password is not used, but make it secure just in case.
- Create a new API token `fail2ban`, user `fail2ban@pve`. A secret will be shown, e.g. `6043ef45-632a-428b-8777-4b1eb5587d58`. Make a copy of this, it is required later.

#### Create a new IPSet

At the Datacenter level, under Firewall, IPSet, create a new empty IPSet. The default used by fail2pvefw is `fail2ban`.

#### Allow access to port 8006 from the VM or CT where fail2ban is running

The Proxmox VE API is running on port 8006, so the VM or CT where fail2ban is running needs access to that port as well; make sure no firewall rule is blocking this.

### On the VM or CT where fail2ban is already running

#### Install the necessary dependencies

##### Add the Proxmox repository

The script uses `libpve-apiclient-perl`, which can be installed from the Proxmox repositories. This is for a Debian 12 VM:

```
wget https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg
echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" >> /etc/apt/sources.list
apt update
apt install libpve-apiclient-perl libdata-validate-ip-perl
```

#### Copy and modify the script fail2pvefw.pl

- Copy the file `fail2pvefw.pl` to a suitable location, e.g. `/root`
- Make sure it's executable
- Edit the file, and update the following 2 lines as necessary; use the secret shown previously.

```
# PVEAPIToken=<user>!<tokenID>=<secret>
my $apitoken = 'PVEAPIToken=fail2ban@pve!fail2ban=6043ef45-632a-428b-8777-4b1eb5587d58';
# Proxmox VE IP address
my $host = qw(192.168.0.1);
```

#### Usage

```
$ /root/fail2pvefw.pl -h
Usage:
    fail2pvefw.pl [-fh] [-i <IPSet>] [-c comment] <ban|unban> <cidr>

      -c,--comment    Comment added (defaults to 'Added on YYYY/MM/DD HH:MM:SS')
      -f,--foreground Do not background the job
      -h,--help       Print this help
      -i,--ipset      IPSet to use - defaults to 'fail2ban'
      -m,--manual     Allow manual SSL certificate verification - implies -f!
      -t,--timestamp  Timestamp of ba, in secs since epoch
```

#### Test that API access works

To test if everything is set up correctly, simply start the script in foreground mode:

```
$ /root/fail2pvefw.pl -f ban 1.2.3.4
```

If no output is produced, it probably worked. Verify this by going to the Proxmox server, and inspect the
`fail2ban` IPSet. It should now include IP address 1.2.3.4.

To remove this IP address from the `fail2ban` IPSet, either use the Proxmox GUI, or run the following:

```
$ /root/fail2pvefw.pl -f unban 1.2.3.4
```

#### Using self-signed certificates

If you're using a self-signed SSL certificate then the SSL verification will fail, and you need to manually approve
the SSL certificate from your server.

```
$ /root/fail2pvefw.pl -m ban 1.2.3.4
The authenticity of host '192.168.0.1' can't be established.
X509 SHA256 key fingerprint is 07:86:CC:BE:@B:48:4C:68:E1:CA:C9:A4:4F:03:77:01:35:55:07:45:38:3B:87:34:63:96:37:76:6E:D5:CB:8E.
Are you sure you want to continue connecting (yes/no)? yes
```

The certificate will be saved to `/var/run/cached_fingerprints.db`, thus avoiding having to approve the certificate in the future.

#### Copy and modify the action fail2pvefw.conf

- Copy the file `fail2pvefw.conf` to `/etc/fail2ban/action.d`.
- Edit the file, and update the /path/to/fail2pvefw.pl as necessary

#### Add the new action to an active jail

A jail can have multiple actions. To add fail2pvefw as an action to a jail, do this:

```
[sshd]
...
banaction = iptables-allports[blocktype=DROP]
            fail2pvefw[name=sshd]
```

## Notes

- Proxmox has this special IPSet called `blacklist` which should block all the IPs in it for everything. Is there a performance benefit to using this IPSet rather than a different IPSet (like `fail2ban` in this case) and explicitely/selectively adding rules to each container to block every IP in this list?
- I'm not sure how usefull this will be in Real Life. What is the performance impact of using an big IPSet on a number of Internet-facing containers? How big is too big, and how fast will bad IPs be collected?
- Besides the performance of the firewall itself, there's also the issue of how much time it takes Fail2Ban to start and stop, because starting and stopping results in all IPs being banned and unbanned, resp.
