# Introduction

EIQ-to-DATP is a simple Python script that will:

1. connect to your EclecticIQ and Microsoft Security Center instances;
2. download all indicators from the EIQ feed;
3. import them into your Defender ATP Custom Indicators.

For configuration options, refer to the `settings.py.sample` file in the `config` directory.

# Requirements

- Python 3
- EIQlib module (https://github.com/KPN-CISO/eiqlib)
- Microsoft Azure AD, Defender ATP API access (with SIEM and Custom Indicator permissions)
- Graph API credentials to generate Graph API tokens
- An EclecticIQ account (user+pass) and EIQ 'Source' token

# Getting started

For EIQ-to-DATP usage:

- Clone the repository
- Rename the `settings.py.sample` file in the `config` directory to `settings.py` 
- Edit the settings in the `settings.py` file to reflect your environment
- Run `./eiq_to_datp.py -h` for help/options

To delete indicators from MDATP:

The `delete_indicator.py` script will let you remove an indicator through the use of the `-i [indicator1] [indicator2] ... [indicatorN]` command-line option. You do not need to know the actual indicator IDs: it is sufficient to simply list the indicator itself, e.g.: `./delete_indicator.py -i 192.168.0.1`.

# Options

Running ./datp-to-eiq.py with `-h` will display help:  

`-v` / `--verbose` will display progress/error info  
`-s` / `--simulate` do not actually ingest anything into EclecticIQ, just pretend (useful with `-v`)  
`-f` / `--feed` select the feed ID from EclecticIQ to downloa, parse and ingest into MDATP  

# Copyright

(c) 2020 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> 

This software is GPLv3 licensed, except where otherwise indicated.
