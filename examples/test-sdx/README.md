# Scalable Synthetic Dataset Generator

## Preparation

``` Bash
# Get policies, mappingss, ribs, and traces  ready

# policies
cp -r ../test-rs/bgp_policies/ ./bgp_policies/

# mappingss
cp ../test-rs/ribs-<ixp-name>/as.* ./ribs-<ixp-name>/

# rib
cp ../test-rs/ribs-<ixp-name>/bview ./ribs-<ixp-name>/
# truncate
../test-rs/gen/truncate_rib.py ./ribs-<ixp-name>/bview 60
# propagate
../test-rs/gen/multi_ribs_gen.py ./ribs-<ixp-name>/bview -f ./bgp_policies/peers_uni_500_020.cfg -a ./ribs-<ixp-name>/asn_2_id.json -d ./ribs-<ixp-name>/

# trace
cp ../test-rs/ribs-<ixp-name>/update ./ribs-<ixp-name>/
```
``` Bash
# generate sdx_global.cfg
./generate_configs.py bgp_policies/peers_uni_500_020.cfg ./ribs-<ixp-name>/

# generate sdn policies
./generate_policies.py ./ribs-<ixp-name>/
```

## Execution
``` Bash
cd ~/iSDX/pctrl-sgdx/
# modify arguements
./all_participants.sh

cd ~/iSDX/pctrl-isdx/
# modify arguements
./all_participants.sh
```
