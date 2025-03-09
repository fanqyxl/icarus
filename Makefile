venv:
	bash scripts/venv.sh

setup-python:
	mkdir -p gen/python
	protoc --python_out=gen/python proto/crs.proto
	protoc --python_out=gen/python proto/pins.proto
	protoc --python_out=gen/python proto/ct.proto
	cp gen/python/proto/crs_pb2.py src/root_store_gen
	cp gen/python/proto/pins_pb2.py src/root_store_gen
	cp gen/python/proto/ct_pb2.py src/root_store_gen
	exit

build-packed-data:
	mkdir -p out/PKIMetadata
	make venv
	make setup-python

ca-keys:
	cd httpmitm; bash generate_certs.sh

clean:
	rm -rf out/
	rm -rf original/
	rm -rf gen
	rm -rf .venv/
	rm -rf src/root_store_gen/*_pb2.py

start-server: 
	bash -c "while tmux has-session -t icarus; do tmux kill-session -t icarus; done"
	echo "set -g mouse on" > ~/.tmux.conf
	tmux new -d -s icarus "cd httpmitm; bash start.sh"
	tmux a -t icarus
