#! /bin/bash

# RIB name fmt: ribs-<ixp-name>-<test-metric:scale,rib,frac,rate>-<as_num>-<rib_size>-<frac>
RIB='ribs-ams-scale'
ASNUMS=( 100 )
RIBSIZES=( 'm' )      # for participant scalablity test, rib_size depends on participant number, set RIBSIZES 'm'
FRACS=( 20 )
XBGP_MODE=0             # 0: time based updates, 1: rate based updates
RATES=( 1 )


for as_num in "${ASNUMS[@]}"
do
    for rib_size in "${RIBSIZES[@]}"
    do
        for fraction in "${FRACS[@]}"
        do
            for rate in "${RATES[@]}"
            do
                if [ -f sig_1 ]
                then
                    rm sig_1
                fi

                if [ -f sig_2 ]
                then
                    rm sig_2
                fi

                ./split_policy.py -f ../examples/test-rs/bgp_policies/peers_uni_${as_num}_0${fraction}.cfg -r ../examples/test-rs/bgp_policies/prefer_rand_${as_num}.cfg
                python prio_handler_rs2.py ../examples/test-rs/${RIB}-${as_num}-${rib_size}-${fraction}/asn_2_id.json &
                python prio_handler_rs1.py ../examples/test-rs/${RIB}-${as_num}-${rib_size}-${fraction}/asn_2_id.json &

                while [[ ( ! -f sig_1 ) || ( ! -f sig_2 ) ]]
                do
                    sleep 2
                done
                rm sig_1
                rm sig_2

                cd ../xbgp/
                python xbgp.py 0 localhost 6000 ../examples/test-rs/${RIB}-${as_num}-${rib_size}-${fraction}/update ${rate} ${XBGP_MODE} --seperate_prefix &
                cd -
                while pgrep -x "ixp.exe" > /dev/null
                do
                    sleep 5
                done
                ./merge_time.py result_1_7760 result_2_7760
                mv result_1_7760_result_2_7760 result_10gts_${RIB}-${as_num}-${rib_size}-${fraction}_${XBGP_MODE}-${RATES}
            done
        done
    done
done
