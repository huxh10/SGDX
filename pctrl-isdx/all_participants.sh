#!/bin/sh

INSTALL_ROOT='/home/xiaohe/iSDX'
EXAMPLE_NAME='test-sdx'
RIB_NAME='ribs-ams-frac'    # frac, scale
FRACS=( 100 80 60 40 20 )
ASNUMS=( 500 )
MODE=0
RATES=( 20 )

touch time
echo "start" > time

for rate in "${RATES[@]}"
do
    #echo $rate >> time
    for as_num in "${ASNUMS[@]}"
    do
        echo $asn >> time
        echo "#### Running for asn $asn ####"
        for fraction in "${FRACS[@]}"
        do
            echo $fraction >> time
            echo "#### Running for fraction $fraction ####"
    	    # Clean DB & Initialize the rib
    	    echo "Cleaning MongoDB & Initializing Participant Rib"
    	    cd $INSTALL_ROOT/pctrl-isdx; ./clean.sh

    	    echo "Starting Reflog..."
    	    cd $INSTALL_ROOT/flanc;  ./reflog.py 0.0.0.0 5555 sdx logger.txt &

    	    # Start Route Server
    	    echo "Starting RouteServer..."
    	    cd $INSTALL_ROOT/xrs;
            if [ -f sig ]
            then
                rm sig
            fi
            python route_server.py $AS_NUM $EXAMPLE_NAME/${RIB_NAME}-${as_num}-${fraction}/ &
            while [ ! -f sig ]
            do
                sleep 0.01
            done
            rm sig

    	    # Start Participant controller
            AS_NUM_RANGE=`expr ${as_num} - 1`
            for i in $(seq 0 $AS_NUM_RANGE)
    	    do
    	    	echo "Starting Participant $i Controller..."
    	    	cd $INSTALL_ROOT/pctrl-isdx; python participant_controller.py $EXAMPLE_NAME ${RIB_NAME}-${as_num}-${fraction} bgp_policies/prefer_rand_${as_num}.cfg $i &
                while [ ! -f $INSTALL_ROOT/xrs/sig ]
                do
                    sleep 0.01
                done
                rm $INSTALL_ROOT/xrs/sig
    	    done
            sleep 3

    	    echo "Starting XBGP..."
    	    cd $INSTALL_ROOT/xbgp; ./xbgp.py 2 localhost 6000 $INSTALL_ROOT/examples/$EXAMPLE_NAME/${RIB_NAME}-${as_num}-${fraction}/update $rate $MODE --seperate_prefix &
            while [ `ps auxf | grep python | wc -l` -ne 2 ]
            do
                sleep 5
            done
            cd $INSTALL_ROOT/pctrl-isdx
            ../plot/get_sgdx_time.py ${as_num} ../xrs/result result/ >> time
        done
    done
done
