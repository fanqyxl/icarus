venv:
	bash venv.sh

setup-python:
	mkdir -p gen/python
	protoc --python_out=gen/python proto/crs.proto
	protoc --python_out=gen/python proto/pins.proto
	protoc --python_out=gen/python cproto/t.proto
	cp gen/python/crs_pb2.py src/root_store_gen
	cp gen/python/pins_pb2.py src/root_store_gen
	cp gen/python/ct_pb2.py src/root_store_gen
	exit

build-packed-data:
	mkdir -p out/PKIMetadata
	make venv
	make setup-python

clean:
	rm -rf out/

start-server: 
	bash -c "while tmux has-session -t icarus; do tmux kill-session -t icarus; done"
	echo "set -g mouse on" > ~/.tmux.conf
	tmux new -d -s icarus "cd httpmitm; bash start_proxy.sh"
	tmux splitw -t icarus -h "cd httpmitm/dmbackend; bash start_server.sh"
	tmux a -t icarus
