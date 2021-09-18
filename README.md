# synology-pihole

<!-- Tagline -->
<p align="center">
    <b>Install or Update Pi-Hole as Docker Container on a Synology NAS with a Static IP Address</b>
    <br />
</p>


<!-- Badges -->
<p align="center">
    <a href="https://github.com/markdumay/synology-pihole/commits/master" alt="Last commit">
        <img src="https://img.shields.io/github/last-commit/markdumay/synology-pihole.svg" />
    </a>
    <a href="https://github.com/markdumay/synology-pihole/issues" alt="Issues">
        <img src="https://img.shields.io/github/issues/markdumay/synology-pihole.svg" />
    </a>
    <a href="https://github.com/markdumay/synology-pihole/pulls" alt="Pulls">
        <img src="https://img.shields.io/github/issues-pr-raw/markdumay/synology-pihole.svg" />
    </a>
    <a href="https://github.com/markdumay/synology-pihole/blob/master/LICENSE" alt="License">
        <img src="https://img.shields.io/github/license/markdumay/synology-pihole.svg" />
    </a>
</p>

<!-- Table of Contents -->
<p align="center">
  <a href="#about">About</a> •
  <a href="#built-with">Built With</a> •
  <a href="#prerequisites">Prerequisites</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#usage">Usage</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#credits">Credits</a> •
  <a href="#donate">Donate</a> •
  <a href="#license">License</a>
</p>


## About
[Pi-hole][pihole_url] is an open-source application that blocks advertisements and internet tracking on a private network. By setting up Pi-hole as DNS server on your local router, all devices connected to your network will automatically benefit from this ad-blocking feature. This script simplifies the setup of Pi-hole on a [Synology][synology_url] network-attached storage (NAS). It uses Docker to isolate Pi-hole from the NAS. It also assigns a static IP address to the Pi-hole instance using a virtual network (macvlan) to prevent any port conflicts. At the moment, the script only supports IPv4.

<!-- TODO: add tutorial deep-link 
Detailed background information is available on the author's [personal blog][blog].
-->

## Built With
The project uses the following core software components:
* [Docker][docker_url] - Container platform (including Compose)
* [Pi-hole][pihole_url] - DNS sinkhole to block unwanted content

## Prerequisites
*Synology-pihole* runs on a Synology NAS with DSM 6 or later. The script has been tested with a DS918+ running `DSM 7.0-41890`. Other prerequisites are:

* **SSH admin access is required** - *synology-pihole* runs as a shell script on the terminal. You can enable SSH access in DSM under `Control Panel ➡ Terminal & SNMP ➡ Terminal`.

* **Docker and Docker Compose are required** - *synology-pihole* runs as a Docker container. Install Docker on your NAS in DSM via `Package Center ➡ All Packages ➡ Docker` and ensure the status is `Running`.

* **A range of at least four local IP addresses needs to be reserved** - *synology-pihole* assigns Pi-hole to a static IP address. To avoid any networking conflicts, a minimum range of four consecutive IP addresses need to be exclusively reserved by your DHCP server. This [calculator][ipcalc] displays the characteristics for a given IP address and netmask (the script defaults to `/30`). Please refer to the manual of your modem and/or DHCP server on how to reserve an IP range.

## Deployment
Deployment of *synology-pihole* is a matter of cloning the GitHub repository. Login to your NAS terminal via SSH first. Assuming you are in the working folder of your choice, clone the repository files. Git automatically creates a new folder `synology-pihole` and copies the files to this directory. Then change your current folder to simplify the execution of the shell script.

```console
git clone https://github.com/markdumay/synology-pihole.git
cd synology-pihole
```

<!-- TODO: TEST CHMOD -->

## Usage
*Synology-pihole* requires `sudo` rights. Use the following command to invoke *synology-pihole* from the command line.

```
sudo ./syno_pihole.sh [OPTIONS] [PARAMETERS] COMMAND
```

As an example, the following command installs Pi-hole on your NAS at the address `192.168.0.250`.

```console
sudo ./syno_pihole.sh --ip 192.168.0.250 install
```

The virtual network does not persist during a reboot. Invoke the following command to recreate the network.
```console
sudo ./syno_pihole.sh --ip 192.168.0.250 network
```

Run the following command to update an existing Pi-hole container if a newer version is available.
```console
sudo ./syno_pihole.sh update
```


### Commands
*Synology-pihole* supports the following commands. 

| Command        | Description |
|----------------|-------------|
| **`install`**  | Installs Pi-hole as Docker container |
| **`network`**  | Creates or recreates virtual network |
| **`update`**   | Updates an existing Pi-hole Docker container |
| **`version`**  | Shows host and Pi-hole versions |

In addition, the following options are available.

| Option | Alias      | Parameter  | Description |
|--------|------------|------------|-------------|
| `-f`   | `--force`  |            | Bypass checks to force the installation / update |
| `-l`   | `--log`    | `LOG FILE` | Redirect output to `LOG FILE` |


*Synology-pihole* supports several advanced settings through either command-line parameters or a `.env` file. An example `sample.env` is available in the git [repository][repository]. The command-line parameters take precedence over settings in the `.env` file.

| Variable          | Parameter       | Required | Example               | Description |
|-------------------|-----------------|----------|----------------------|-------------|
| `PIHOLE_IP`       | -i, --ip        | `Yes`    | `192.168.0.250`      | Static IP address of Pi-hole, ensure this IP address is available |
| `INTERFACE`       | -n, --interface | `No`     | `eth0`               | Host network interface to the subnet, auto-detected if omitted |
| `SUBNET`          | -s, --subnet    | `No`     | `192.168.0.0/24`     | CIDR notated subnet the Pi-Hole will join, auto-detected if omitted |
| `GATEWAY`         | -g, --gateway   | `No`     | `192.168.0.1`        | Subnet gateway router address (see --subnet), auto-detected if omitted |
| `HOST_IP`         | --host-ip       | `No`     | `192.168.0.3`        | New host address for communicating with Pi-hole via macvlan bridge interface. By default the lowest address starting at the first (not the Pi-hole address) of the Docker network range (see --range) is used |
| `IP_RANGE`        | -r, --range     | `No`     | `192.168.0.250/30`   | CIDR notated address range for Docker to assign to containers attached to the created 'Docker macvlan Network', defaults to `PIHOLE_IP/32` |
| `VLAN_NAME`       | -v, --vlan      | `No`     | `macvlan0`           | Name assigned to the generated macvlan interface on the host to enable container <-> host communication (defaults to `macvlan0`) |
| `MAC_ADDRESS`     | -m, --mac       | `No`     | `70:d9:5a:70:99:cd`  | Unicast MAC to assign Pi-hole, randomized if omitted |
| `DOMAIN_NAME`     | -d, --domain    | `No`     | `example.com` | Fully qualified domain of the subnet |
| `PIHOLE_HOSTNAME` | -H, --host      | `No`     | `pihole`             | Hostname of Pi-hole, defaults to `pihole` |
| `TIMEZONE`        | -t, --timezone  | `No`     | `Europe/Amsterdam`   | Local Timezone (see [Wikipedia][timezone_list] for an overview, auto-detected if omitted) |
| `DNS1`            | --DNS1          | `No`     | `1.1.1.1`            | Primary DNS provider to be used by Pi-hole (see this [list][upstream_dns] for typical providers) |
| `DNS2`            | --DNS2          | `No`     | `1.0.0.1`            | Alternative DNS provider to be used by Pi-hole |
| `DATA_PATH`       | --path          | `No`     | `./data`             | Host data location path for Pi-hole, defaults to `./data` |
| `WEBPASSWORD`     | -p, --password  | `No`     | `password`           | Password for the Pi-hole administrative web interface (prompted for when omitted) |

### Scheduled Tasks
#### Updating Pi-Hole to the Latest Version
It is recommended to schedule a task to ensure Pi-hole uses the latest  version available. Follow these steps to do so.
1. Access `Task Scheduler` via `Control Panel ➡ Task Scheduler` in DSM. 
2. Now click on `Create ➡ Scheduled Task ➡ User-defined script` to create a custom script. Give the task a familiar name in the tab `General`, such as `Update Pi-hole container`, and select `root` as user. 
3. Schedule the task in the tab `Schedule`, for example running it at 00:00 daily. 
4. Finally, enter the following script in the user-defined script section of the `Task Settings` tab. Be sure to update `/path/to/your/script/`. The optional instruction `-l /var/log/syno_pihole.log` copies all messages to a log file.
    ```console
    /bin/sh /path/to/your/script/syno_pihole.sh update -l /var/log/syno_pihole.log
    ```

#### Ensuring the Host <-> Container Bridge Interface is Available After Reboot
By default, Docker containers are automatically restarted after a system reboot. However, the macvlan bridge interface setup by `synology-pihole` is lost after a system reboot and/or update. Similar to the instructions in the previous paragraph, you can setup a task to automatically recreate it during the boot process of your Synology NAS. Follow these steps to do so.
1. Access `Task Scheduler` via `Control Panel ➡ Task Scheduler` in DSM. 
2. Now click on `Create ➡ Triggered Task ➡ User-defined script` to create a custom script. Give the task a familiar name in the tab `General`, such as `Recreate Pi-hole Bridge Interface`.
3. In the same screen, select `root` as user and `Boot-up` as event.
4. Finally, enter the following script in the user-defined script section of the `Task Settings` tab. Be sure to update `/path/to/your/script/`. The optional instruction `-l /var/log/syno_pihole.log` copies all messages to a log file. The option `--force` is required to avoid the script asking for user confirmation.
    ```console
    /bin/sh /path/to/your/script/syno_pihole.sh network --ip 192.168.0.250 --log /var/log/syno_pihole.log --force
    ```

### Configuration
The Pi-hole [FAQ][pihole_dns] describes various options on how to configure the Pi-hole DNS server. The Pi-hole administrator web interface is available by navigating to `http://ip_address/admin/` (replacing `ip_address` with the correct IP address).


## Contributing
1. Clone the repository and create a new branch 
    ```console
    git checkout https://github.com/markdumay/synology-pihole.git -b name_for_new_branch
    ```
2. Make and test the changes
3. Submit a Pull Request with a comprehensive description of the changes

## Credits
*Synology-pihole* is inspired by the following code repositories and blog articles:
* Bram van Dartel (xirixiz) - [Setup Pi-hole on a virtual LAN][gist_xirixiz]
* Tony Lawrence - [Free your Synology ports for Docker][article_tonylawrence]
* Lars Kellogg-Stedman - [Using Docker macvlan networks][article_oddbit]
* Steven Welsh (beefyfish) - [Pi-hole on Synology NAS (Docker Version)][article_beefyfish]

## Donate
<a href="https://www.buymeacoffee.com/markdumay" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/lato-orange.png" alt="Buy Me A Coffee" style="height: 51px !important;width: 217px !important;"></a>

## License
<a href="https://github.com/markdumay/synology-pihole/blob/master/LICENSE" alt="License">
    <img src="https://img.shields.io/github/license/markdumay/synology-pihole.svg" />
</a>

Copyright © [Mark Dumay][blog]



<!-- MARKDOWN PUBLIC LINKS -->
[docker_url]: https://docker.com
[synology_url]: https://www.synology.com
[synology_docker]: https://www.synology.com/en-us/dsm/packages/Docker
[synology_boot]: https://help.synology.com/developer-guide/integrate_dsm/run_with_system_boot.html
[pihole_url]: https://pi-hole.net
[pihole_dns]: https://discourse.pi-hole.net/t/how-do-i-configure-my-devices-to-use-pi-hole-as-their-dns-server/245
[upstream_dns]: https://docs.pi-hole.net/guides/upstream-dns-providers/
[gist_xirixiz]: https://gist.github.com/xirixiz/ecad37bac9a07c2a1204ab4f9a17db3c
[article_tonylawrence]: https://tonylawrence.com/posts/unix/synology/free-your-synology-ports/
[article_oddbit]: https://blog.oddbit.com/post/2018-03-12-using-docker-macvlan-networks/
[article_beefyfish]: https://discourse.pi-hole.net/t/setup-on-synology-docker/18067/4

[timezone_list]: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
[mac_test]: http://sqa.fyicenter.com/1000208_MAC_Address_Validator
[ipcalc]: http://jodies.de/ipcalc


<!-- MARKDOWN MAINTAINED LINKS -->
<!-- TODO: add blog link
[blog]: https://markdumay.com
-->
[blog]: https://github.com/markdumay
[repository]: https://github.com/markdumay/synology-pihole.git
