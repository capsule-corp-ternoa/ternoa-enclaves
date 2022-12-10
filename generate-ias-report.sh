gramine-sgx-ias-request report \
    --api-key 8c24d40395704d3b825a4bbd695bab03 \
    --quote-path quote/enclave.quote \
    --report-path quote/ias.report \
    --sig-path quote/ias.sig \
    --cert-path quote/ias.cert \
    -v > quote/report.log 2>&1 &

