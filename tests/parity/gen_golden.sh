#!/usr/bin/env bash
cd /mnt/d/rust_code/rDpi || exit 1
for n in http_connect http_proxy doh_resolver dot_alpn dot_port ftp_transfer; do
  /mnt/d/c_code/nDPI-5.0/build/example/ndpiReader -i "tests/parity/corpus/$n.pcap" -k "tests/parity/golden/$n.ndpi.json" -K json >/dev/null 2>&1
done
echo DONE
