all:
	gcc pbproxy.c -lcrypto -lpthread -o pbproxy
clean:
	rm -rf pbproxy
ssh_example_client:
	ssh -o "ProxyCommand ./pbproxy -k mykey localhost 2222" localhost
ssh_example_proxy:
	./pbproxy -k mykey -l 2222 localhost 22
