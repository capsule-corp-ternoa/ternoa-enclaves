
cargo build --release
make SGX=1 start-gramine-server >> make.log 2>&1 &

echo -n "Initializing encalve ..."
while ! (test -f "enclave.log") || ! (grep -q "Port 3000" "enclave.log"); do
	echo -n "."
	sleep 1
done

echo -e "\n"
echo "Getting Report from IAS ..."

./generate-ias-report.sh

echo "IAS Report is ready."
