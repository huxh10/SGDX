## Installation
1. ripencc bgpdump

## Inputs
mkdir ribs-<ixp-name> && cd ribs-<ixp-name>
wget [RIS Raw Data](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data)

## Configuration
cd ../gen/

BGP Policies
./bgp_policy_gen.py AS_SIZE --rank_policies --filter_policies

Splitted Policies
cd ~/iSDX/pprs/
./split_policy.py -f ../examples/test-rs/bgp_policies/peers_uni_500_020.cfg -r ../examples/test-rs/bgp_policies/prefer_rand_500.cfg
cd -

AS Mappings
./as_map_gen.py ../ribs-ams/bview --as_num 500 --cfg_dir ../ribs-ams/

Truncate Rib if neccessary (one rib entry costs around 400B, max heap size using SGX is around 33GB in our 64GB RAM server)
./truncate_rib.py ../ribs-ams/bview 8

Seperated Ribs
./multi_ribs_gen.py ../ribs-ams/bview -f ../bgp_policies/peers_uni_500_020.cfg -a ../ribs-ams/asn_2_id.json -d ../ribs-ams/

## Execution
cd ~/iSDX/
./run_sgx_rs.sh
./run_six_pack_rs.sh
