# OCS Agent Unix Packager

<p align="center">
  <img src="https://cdn.ocsinventory-ng.org/common/banners/banner660px.png" height=300 width=660 alt="Banner">
</p>

<h1 align="center">OCS Agent Standalone Unix Packager</h1>
<p align="center">
  <b>Some Links:</b><br>
  <a href="http://ask.ocsinventory-ng.org">Ask question</a> |
  <a href="https://www.ocsinventory-ng.org/?utm_source=github-ocs">Website</a> |
  <a href="https://www.ocsinventory-ng.org/en/#ocs-pro-en">OCS Professional</a>
</p>

## Description

The aim of this script is to create a all in one package to be deployed on every Linux machine.
The package embeds compiled Perl for the related OS, OCS Agent perl package, and all required perl mudules.

* packageOCSAgent.config: packager configuration
    * PROXY_HOST if you have direct Internet connection
    * OCS_INSTALL_DIR: OCS Agent installation directory
    * PERL_VERSION: Perl version you want to compile and embed in OCS package
    * PERL_DL_LINK: Perl sources download link
    * EXPAT_DL_LINK: Expat sources download link
    * OCSAGENT_DL_LINK: OCS Agent sources download link
    * NMAP_DL_LINK: Nmap sources download link
    * OCS_AGENT_CRONTAB: ```[0-1]``` Create script to add crontab on system
    * OCS_AGENT_CRONTAB_HOUR: How many hour between each crontab call
    * OCS_AGENT_LAZY: ```[0-1]``` Activate lazy mode on Agent
    * OCS_AGENT_TAG: Set default tag
    * OCS_SERVER_URL: Set server URL
    * OCS_SSL_ENABLED: ```[0-1]``` Enable SSL check
    * OCS_SSL_CERTIFICATE_FULL_PATH: Path to the certificate
    * OCS_LOG_FILE: ```[0-1]``` Enable file logging feature
    * OCS_LOG_FILE_PATH: Set the log path file
* PerlModulesDownloadList.txt: download URL for all Perl modules dependencies
* packageOCSAgent.sh: packager script

## Usage

As root user
```shell
#./packageOCSAgent.sh
```

Output is a tar/gz archive: ocsinventory-agent_*LinuxDistribution*_*MajorVersion*.tar.gz

## Installation on target system

As root user
```shell
cd /
tar zvf /path/to/archive/ocsinventory-agent-xxx.tar.gz
/opt/ocsinventory/scripts/create_crontab.sh
```

For starting inventarization manually you can use

```shell
/opt/ocsinventory/scripts/execute_agent.sh
```

## Todo

1. Bypass current limitations
2. Less dirty openssl detection, reduce number of hacks in source compilation

## Current Limitation

1. nmap command line path is not referenced in Perl module, thus, IP Discovery function does not work
