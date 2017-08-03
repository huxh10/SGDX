#! /bin/bash

RIB=$1
AS_NUM=$2

if [ -f ./pprs//sig_1 ]
then
    rm ./sxrs/sig_1
fi

if [ -f ./pprs//sig_2 ]
then
    rm ./sxrs/sig_2
fi

cd ./pprs/
./split_policy.py -f ../examples/test-rs/bgp_policies/peers_uni_${AS_NUM}_020.cfg -r ../examples/test-rs/bgp_policies/prefer_rand_${AS_NUM}.cfg
python prio_handler_rs2.py ../examples/test-rs/$RIB/asn_2_id.json -r ../examples/test-rs/$RIB/bview &
python prio_handler_rs1.py ../examples/test-rs/$RIB/asn_2_id.json -r ../examples/test-rs/$RIB/bview &
cd ..

while [[ ( ! -f ./pprs/sig_1 ) || ( ! -f ./pprs/sig_2 ) ]]
do
    sleep 2
done
rm ./pprs/sig_1
rm ./pprs/sig_2

cd ./xbgp/
python xbgp.py 0 localhost 6000 ../examples/test-rs/$RIB/update 1 0 &
#python xbgp.py 0 localhost 6000 update 1 2
