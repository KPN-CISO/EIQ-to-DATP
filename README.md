# Introduction

EIQ-to-EMAIL is a simple Python script that will:

1. connect to your EclecticIQ instance;
2. download all indicators from the EIQ feed;
3. send e-mail notifications to the users about the items in the feed.

For configuration options, refer to the `settings.py.sample` file in the `config` directory.

# Requirements

- Python 3
- EIQlib module (https://github.com/KPN-CISO/eiqlib)
- An EclecticIQ account (user+pass) and EIQ 'Source' token
- An SMTP server to send the e-mails (obviously!)

# Getting started

For EIQ-to-EMAIL usage:

- Clone the repository
- Rename the `settings.py.sample` file in the `config` directory to `settings.py` 
- Edit the settings in the `settings.py` file to reflect your environment
- Run `./eiq_to_email.py -h` for help/options

# Options

Running ./eiq_to_email.py with `-h` will display help:  

`-v` / `--verbose` will display progress/error info  
`-s` / `--simulate` do not actually ingest anything into EclecticIQ, just pretend (useful with `-v`)  
`-f` / `--feed` select the feed ID from EclecticIQ to downloa, parse and ingest into MDATP  

# Copyright

(c) 2021 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> 

This software is GPLv3 licensed, except where otherwise indicated.
