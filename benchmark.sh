#!/bin/bash

# Usage: ./run_benchmarks_powers.sh start_exp end_exp
# Example: ./run_benchmarks_powers.sh 2 8  # runs for 2^2=4 up to 2^8=256 issuers

start_exp=$1
end_exp=$2

if [ -z "$start_exp" ] || [ -z "$end_exp" ]; then
  echo "Usage: $0 <start_exponent> <end_exponent>"
  exit 1
fi

for (( exp=start_exp; exp<=end_exp; exp++ ))
do
  issuers=$((2**exp))
  echo "Running benchmark with $issuers issuers..."
  #yarn ts-node --esm ./src/test/full_test_main.js --claims 1024 --size 64 --issuers $issuers --runs 30
  #yarn ts-node --esm ./src/test/full_sizes_test_main.js --claims 1024 --size 64 --issuers $issuers --runs 30
  #yarn ts-node --esm ./src/test/full_sizes_test_main.js --claims 256 --size 64 --issuers $issuers --runs 30
  #yarn ts-node --esm ./src/test/full_sizes_test_main.js --claims 16 --size 64 --issuers $issuers --runs 30
  #yarn ts-node --esm ./src/test_no_multisign/full_test_standard_veramo.js --claims 64 --size 64 --issuers $issuers --runs 30
  #yarn ts-node --esm ./src/test_no_multisign/full_test_standard_veramo.js --claims 64 --size 64 --issuers $issuers --runs 30
  #yarn ts-node --esm ./src/test_no_multisign/full_sizes_standard_test_main.js --claims 1024 --size 64 --issuers $issuers --runs 30  yarn ts-node --esm ./src/test_no_multisign/full_sizes_standard_test_main.js --claims 1024 --size 64 --issuers $issuers --runs 30
  yarn ts-node --esm ./src/test_no_multisign/full_sizes_standard_test_main.js --claims 256 --size 64 --issuers $issuers --runs 30
  #yarn ts-node --esm ./src/test_no_multisign/full_sizes_standard_test_main.js --claims 16 --size 64 --issuers $issuers --runs 30
  echo "Done with $issuers issuers"
done
