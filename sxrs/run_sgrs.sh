#! /bin/bash

# RIB name fmt: ribs-<ixp-name>-<test-metric:scale,rib,frac,rate>-<as_num>-<rib_size>-<frac>
RIB='ribs-ams-scale'
PROCS=( 'rs_w_sgx' 'rs_wo_sgx' )
ASNUMS=( 500 )
RIBSIZES=( 'm' )      # for participant scalablity test, rib_size depends on participant number, set RIBSIZES 'm'
FRACS=( 20 )
XBGP_MODE=0             # 0: time based updates, 1: rate based updates
RATES=( 1 )

for PROC in "${PROCS[@]}"
do
    for as_num in "${ASNUMS[@]}"
    do
        for rib_size in "${RIBSIZES[@]}"
        do
            for fraction in "${FRACS[@]}"
            do
                for rate in "${RATES[@]}"
                do
                    if [ -f sig ]
                    then
                        rm sig
                    fi

                    ./$PROC -a ../examples/test-rs/${RIB}-${as_num}-${rib_size}-${fraction}/asn_2_id.cfg -i ../examples/test-rs/${RIB}-${as_num}-${rib_size}-${fraction}/as_ips.cfg -f ../examples/test-rs/bgp_policies/peers_uni_${as_num}_0${fraction}.cfg -r ../examples/test-rs/bgp_policies/prefer_rand_${as_num}.cfg -d ../examples/test-rs/${RIB}-${as_num}-${rib_size}-${fraction}/ &

                    while [ ! -f sig ]
                    do
                        sleep 2
                    done
                    rm sig

                    cd ../xbgp/
                    python xbgp.py 1 localhost 6000 ../examples/test-rs/${RIB}-${as_num}-${rib_size}-${fraction}/update ${rate} ${XBGP_MODE} --seperate_prefix &
                    cd -
                    while pgrep -x ${PROC} > /dev/null
                    do
                        sleep 2
                    done
                    cp result ./result_rs/result_${PROC}_${RIB}-${as_num}-${rib_size}-${fraction}_${XBGP_MODE}-${RATES}
                done
            done
        done
    done
done
