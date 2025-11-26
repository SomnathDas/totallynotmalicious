### To build stager and run sample payload
```bash
make clean
make
./stager payload
```

### Changes
- (Main-Change) Parsing "payload" ELF and extracting AddressMap at runtime (previously at buildtime) via Capstone.
- (Sub-Change) Calculating Runtime Address = Runtime Base + Offset to create AddressMap.

### References
POC Sample based on [https://arxiv.org/pdf/2111.13894](https://arxiv.org/pdf/2111.13894)
