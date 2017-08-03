#!/bin/sh

INSTALL_ROOT='/home/xiaohe/iSDX'
EXAMPLE_NAME='test-sdx'
RIB_NAME='ribs-500'
RANK_NAME='bgp_policies/prefer_rand_500.cfg'
UPDATE_FILE='../examples/test-sdx/ribs-500/update'
ITERATIONS=1
FRAC=( 0.8 )
RATE=5
MODE=0
AS_NUM=500

for iter in `seq 1 $ITERATIONS`
do
	echo "#### Running for Iteration $iter ####"
	for fraction in "${FRAC[@]}"
	do
		# Clean DB & Initialize the rib
		echo "Cleaning MongoDB & Initializing Participant Rib"
		cd $INSTALL_ROOT/pctrl-isdx; ./clean.sh

		# Initialize Ribs
		echo "Initialize Ribs"
		cd $INSTALL_ROOT/pctrl-isdx; python initialize_ribs.py $EXAMPLE_NAME $RIB_NAME $RANK_NAME

		echo "Starting Reflog..."
		cd $INSTALL_ROOT/flanc;  ./reflog.py 0.0.0.0 5555 sdx logger.txt &

		# Start Route Server
		echo "Starting RouteServer..."
		cd $INSTALL_ROOT/xrs;
	    if [ -f sig ]
        then
            rm sig
        fi
        python route_server.py $AS_NUM $EXAMPLE_NAME/$RIB_NAME/ &
        while [ ! -f sig ]
        do
            sleep 0.01
        done
        rm sig

		# Start Participant controller
        AS_NUM_RANGE=`expr $AS_NUM - 1`
        for i in $(seq 0 $AS_NUM_RANGE)
		do
			echo "Starting Participant $i Controller..."
			cd $INSTALL_ROOT/pctrl-isdx; python participant_controller.py $EXAMPLE_NAME $RIB_NAME $RANK_NAME $i &
            while [ ! -f $INSTALL_ROOT/xrs/sig ]
            do
                sleep 0.01
            done
            rm $INSTALL_ROOT/xrs/sig
		done
        sleep 3

		echo "Starting XBGP..."
		cd $INSTALL_ROOT/xbgp; ./xbgp.py 2 localhost 6000 $UPDATE_FILE $RATE $MODE --seperate_prefix &
	done
done
