#!/bin/bash
output_file="remap-path.env"
echo -n 'RUSTFLAGS="-A warnings' > $output_file
find ./ -type f -path "./malefic*" -name "*.rs" | sed 's|^\./||' | while read rs_file; do
    random_value=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
    echo -n "--remap-path-prefix=${rs_file}=${random_value}.rs " >> $output_file
done
echo -n '"' >> $output_file
echo "Generated $output_file"
