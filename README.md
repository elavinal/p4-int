v1.0:

1/Run project with 'make'

2/Open hosts with :
	xterm h1 h2 h4

3/Configure the wanted network data in config/config.yaml
  Or write a new one with the same fields

4/In another terminal :
  Update network behavior with 'make int' if you want to use the config/config.yaml
  To use another config file update with 'make CONFIG=myFilePath int'

5/On h2:
  Execute command : 'cd collector'.
  Run : './receive_int.py' if you just want to monitor metadata.
  or : './receive_int.py --o <csv_name>' if you want to save metadata in a CSV file.

6/On h4 run :
	./receive.py

7/On h1 run :
	./send.py 10.0.4.4 1234 "INT is nice !"

	
h2 should receive the INT report and h4 a message without INT headers (except for some metadata traces)

TODO : Find a way to make the collector in python3
