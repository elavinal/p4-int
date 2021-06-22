# P4-int

## Run:

v1.0:

1/Run project with 'make'

2/Open hosts with :
  - xterm h1 h2 h4

3/Configure the wanted network data in config/config.yaml
  - Or write a new one with the same fields

4/In another terminal :
  - Update network behavior with 'make int' if you want to use the config/config.yaml
  - To use another config file update with 'make CONFIG=myFilePath int'

5/On h2:
  - Execute command : 'cd collector'.
  - Run : './receive_int.py' if you just want to monitor metadata.
  - Or : './receive_int.py --o <csv_name>' if you want to save metadata in a CSV file.

6/On h4 run :
  - ./receive.py

7/On h1 run :
  - ./send.py 10.0.4.4 1234 "INT is nice !"

	
h2 should receive the INT report and h4 a message without INT headers (except for some metadata traces)

## Getting Started

- Follow the p4-guide accordingly to you distribution : https://github.com/jafingerhut/p4-guide

- If your distribution is Ubuntu 20.04 or higher you might have to install pip2 and python 2 by hand.
  If so, follow this guide : https://linuxize.com/post/how-to-install-pip-on-ubuntu-20.04/

- P4C is required to compile the different P4 programs and can be obtained here : https://github.com/p4lang/p4c

