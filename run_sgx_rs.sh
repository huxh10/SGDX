#! /bin/bash

PROC=$1
RIB=$2
ASNUM=$3

if [ -f ./sxrs/sig ]
then
    rm ./sxrs/sig
fi

cd ./sxrs/
./$PROC -a ../examples/test-rs/$RIB/asn_2_id.cfg -i ../examples/test-rs/$RIB/as_ips.cfg -f ../examples/test-rs/bgp_policies/peers_uni_${ASNUM}_020.cfg -r ../examples/test-rs/bgp_policies/prefer_rand_${ASNUM}.cfg -d ../examples/test-rs/$RIB/ &
cd ..

while [ ! -f ./sxrs/sig ]
do
    sleep 2
done
rm ./sxrs/sig

cd ./xbgp/
python xbgp.py 1 localhost 6000 ../examples/test-rs/$RIB/update 1 0 &
#python xbgp.py 1 localhost 6000 update 1 2
