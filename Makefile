BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs
DATA_DIR = data

P4C = p4c-bm2-ss

ifndef CONFIG
CONFIG = config/config.yaml
endif

all: run

run: build
	sudo -E python3 run_exercise.py -t topo/topology.json -b simple_switch_grpc
#	sudo python controller/network_setup.py

stop:
	sudo mn -c

build: dirs
	$(P4C) --p4v 16 --p4runtime-files $(BUILD_DIR)/basic_switch.p4.p4info.txt -o build/basic_switch.json p4/basic_switch.p4
	$(P4C) --p4v 16 --p4runtime-files $(BUILD_DIR)/source_switch.p4.p4info.txt -o build/source_switch.json p4/source_switch.p4
	$(P4C) --p4v 16 --p4runtime-files $(BUILD_DIR)/transit_switch.p4.p4info.txt -o build/transit_switch.json p4/transit_switch.p4
	$(P4C) --p4v 16 --p4runtime-files $(BUILD_DIR)/sink_switch.p4.p4info.txt -o build/sink_switch.json p4/sink_switch.p4

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR) $(DATA_DIR)

int:
	sudo python3 controller/int_update.py --config $(CONFIG)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR) $(DATA_DIR)