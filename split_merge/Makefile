include ../utils/Makefile

BMV2_SWITCH_EXE = simple_switch_grpc
NO_P4 = true
P4C_ARGS = --p4runtime-file $(basename $@).p4info --p4runtime-format text
GTOPO = topology_grpc.json

grun: build
	sudo python $(RUN_SCRIPT) -t $(GTOPO) -j build/SplitMerge.json -b simple_switch_grpc
#p4c-bm2-ss --p4v 16 --p4runtime-file build/SplitMerge.p4info --p4runtime-format text -o build/SplitMerge.json SplitMerge.json

