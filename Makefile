BUILD_DIR = build
SRC_DIR = p4
PCAP_DIR = pcaps
LOG_DIR = logs
LOG_LEVEL = trace

P4C = p4c-bm2-ss

BASIC = $(BUILD_DIR)/basic_switch.json
SOURCE = $(BUILD_DIR)/source_switch.json
TRANSIT = $(BUILD_DIR)/transit_switch.json
SINK = $(BUILD_DIR)/sink_switch.json

s01-run: build
	sudo -E python3 run.py -t scenario-01/topology.json -b simple_switch_grpc -L $(LOG_LEVEL)

s01-int:
	sudo python3 controller/config_int.py --dir scenario-01

s02-run: build
	sudo -E python3 run.py -t scenario-02/topology.json -b simple_switch_grpc -L $(LOG_LEVEL)

s02-int:
	sudo python3 controller/config_int.py --dir scenario-02	

build: dirs $(BASIC) $(SOURCE) $(TRANSIT) $(SINK)

# ex: p4c-bm2-ss --p4v 16
#                --p4runtime-files build/source_switch.p4.p4info.txt
#                -o build/source_switch.json
#				 p4/source_switch.p4
$(BUILD_DIR)/%.json: $(SRC_DIR)/%.p4 
	$(P4C) --p4v 16 --p4runtime-files $(BUILD_DIR)/$*.p4.p4info.txt -o $@ $<

dirs:
	@if [ ! -d $(BUILD_DIR) ]; then mkdir -p $(BUILD_DIR); fi
	@if [ ! -d $(LOG_DIR) ]; then mkdir -p $(LOG_DIR); fi
	@if [ ! -d $(PCAP_DIR) ]; then mkdir -p $(PCAP_DIR); fi

stop:
	sudo mn -c

clean: stop
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
