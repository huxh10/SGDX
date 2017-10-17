# Scalable Synthetic Dataset Generator

## Installation
Install [ripencc bgpdump](https://bitbucket.org/ripencc/bgpdump/wiki/Home) to convert binary MRT files to readable(parseable) files.

## Seed Inputs

``` Bash
mkdir ribs-<ixp-name> && cd ribs-<ixp-name>

# download updates.<time>.gz and bview.<time>.gz (RIBs, i.e. historical updates)
wget [RIS Raw Data](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data)

# conversion
bgpdump updates.<time>.gz -O updates
bgpdump bview.<time>.gz -O bview
```

## Configuration

``` Bash
cd .. && mkdir bgp_policies && cd gen

# generate routing policies
./bgp_policy_gen.py AS_SIZE --rank_policies --filter_policies

# generate participant mapping (asn_2_id.json, asn_2_id.cfg, as_ips.cfg)
# extend participants if the specified AS_SIZE is larger than current participant number
./as_map_gen.py ../ribs-<ixp-name>/bview --as_num AS_SIZE --cfg_dir ../ribs-<ixp-name>/

# Truncate Rib if neccessary (one rib entry costs around 400B, max heap size using SGX is around 50GB in our 64GB RAM server)
./truncate_rib.py ../ribs-<ixp-name>/bview 8

# Proagate the RIB to each participant to generate participants' own RIBs
./multi_ribs_gen.py ../ribs-<ixp-name>/bview -f ../bgp_policies/peers_uni_500_020.cfg -a ../ribs-<ixp-name>/asn_2_id.json -d ../ribs-<ixp-name>/
```

## Execution

``` Bash
cd ~/iSDX/sxrs/
# modify arguements
./run_sgx_rs.sh

cd ~/iSDX/pprs/
# modify arguements
./run_sixpack_rs.sh
```
