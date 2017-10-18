#!/bin/sh

INSTALL_ROOT='/home/xiaohe/iSDX'
EXAMPLE_NAME='test-sdx'
RIB_NAME='ribs-ams-scale'   # scale or frac
PROCS=( 'rs_w_sgx' 'rs_wo_sgx' )
ASNUMS=( 200 400 600 800 1000 )
FRACS=( 20 )
MODE=0
rate=20

touch time
echo "start" > time

for process in "${PROCS[@]}"
do
    echo $process >> time
    for as_num in "${ASNUMS[@]}"
    do
        for fraction in "${FRACS[@]}"
        do
            echo $as_num >> time
            echo "#### Running for as_num $as_num ####"

            killall python
            pkill rs_.*

            if [ $process = 'rs_w_sgx' ]
            then
                cd $INSTALL_ROOT/sxrs; cp enclave/enclave.config.xml.${as_num} enclave/enclave.config.xml
                make clean && make
            fi

            echo "Starting Reflog..."
            cd $INSTALL_ROOT/flanc;  ./reflog.py 0.0.0.0 5555 sdx logger.txt &

            echo "Starting RouteServer..."
            cd $INSTALL_ROOT/sxrs;
            if [ -f sig ]
            then
                rm sig
            fi
            ./$process -a $INSTALL_ROOT/examples/$EXAMPLE_NAME/${RIB_NAME}-${as_num}-${fraction}/asn_2_id.cfg -i $INSTALL_ROOT/examples/$EXAMPLE_NAME/${RIB_NAME}-${as_num}-${fraction}/as_ips.cfg -f $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/peers_uni_${as_num}_0${fraction}.cfg -r $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/prefer_rand_${as_num}.cfg -d $INSTALL_ROOT/examples/$EXAMPLE_NAME/${RIB_NAME}-${as_num}-${fraction}/ &
            while [ ! -f sig ]
            do
                sleep 2
            done
            rm sig

            # Start Participant controller
            AS_NUM_RANGE=`expr $as_num - 1`
            for i in $(seq 0 $AS_NUM_RANGE)
            do
            	echo "Starting Participant $i Controller..."
            	cd $INSTALL_ROOT/pctrl-sgdx; python participant_controller.py $EXAMPLE_NAME/${RIB_NAME}-${as_num}-${fraction}/ $i &
                while [ ! -f $INSTALL_ROOT/sxrs/sig ]
                do
                    sleep 0.01
                done
                rm $INSTALL_ROOT/sxrs/sig
            done
            sleep 3

            echo "Starting XBGP..."
            cd $INSTALL_ROOT/xbgp; ./xbgp.py 2 localhost 6000 $INSTALL_ROOT/examples/$EXAMPLE_NAME/${RIB_NAME}-${as_num}-${fraction}/update $rate $MODE --seperate_prefix &
            while [ `ps auxf | grep python | wc -l` -ne 2 ]
            do
                sleep 5
            done
            cd $INSTALL_ROOT/pctrl-sgdx
            ../plot/get_sgdx_time.py ${as_num} ../sxrs/result result/ >> time
        done
    done
done
