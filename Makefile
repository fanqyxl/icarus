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

ca-keys:
	cd httpmitm; bash generate_certs.sh

clean:
	rm -rf out/
	rm -rf original/
	rm -rf gen
	rm -rf .venv/
	rm -rf src/root_store_gen/*_pb2.py
