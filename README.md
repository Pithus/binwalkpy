binwalkpy
===

This is a python interface to binwalk's rust API.



## Usage:

```python
import binwalkpy

bw = binwalkpy.Binwalk(
    target_file_name="/tmp/binwalk/gzip.bin",
    output_directory="/tmp/binwalk/_extracted",
    exclude=["png", "jpeg"],
    full_search=False,
)

print("Target:", bw.base_target_file)
print("Output:", bw.base_output_directory)
print("Signatures:", bw.signature_count)

results = bw.scan_file()
print(results)

extractions = bw.extract_file()
print(extractions)
```
