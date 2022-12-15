BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )/
API_KEY=8c24d40395704d3b825a4bbd695bab03
QUOTEPATH=$BASEDIR/credentials/quote/

gramine-sgx-ias-request report \
			--api-key $API_KEY \
			--quote-path $QUOTEPATH/enclave.quote \
			--report-path $QUOTEPATH/ias.report \
			--sig-path $QUOTEPATH/ias.sig \
			--cert-path $QUOTEPATH/ias.cert \
			-v > $QUOTEPATH/report.log 2>&1 &

