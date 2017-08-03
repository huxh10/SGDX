#!/bin/sh

INSTALL_ROOT='/home/xiaohe/iSDX'
EXAMPLE_NAME='test-sdx'
RIB_NAME='ribs-500'
RS='rs_w_sgx'
UPDATE_FILE='../examples/test-sdx/ribs-500/update'
ITERATIONS=1
FRAC=( 0.2 )
RATE=5
MODE=0
AS_NUM=500

#cd $INSTALL_ROOT/examples/$EXAMPLE_NAME; python generate_configs.py; cp $INSTALL_ROOT/examples/$EXAMPLE_NAME/config/asn_2_* $INSTALL_ROOT/pctrl

for iter in `seq 1 $ITERATIONS`
do
	echo "#### Running for Iteration $iter ####"
	for fraction in "${FRAC[@]}"
	do

		# Generate Policies & Copy asn json files
		#echo "Generating policies for $fraction"
		#cd $INSTALL_ROOT/examples/$EXAMPLE_NAME; python generate_policies.py $fraction
	
        killall python
        pkill rs_.*

		echo "Starting Reflog..."
		cd $INSTALL_ROOT/flanc;  ./reflog.py 0.0.0.0 5555 sdx logger.txt &

		echo "Starting RouteServer..."
		cd $INSTALL_ROOT/sxrs;
        if [ -f sig ]
        then
            rm sig
        fi
        #valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./$RS -a $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/asn_2_id.cfg -i $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/as_ips.cfg -f $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/peers_uni_500_020.cfg -r $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/prefer_rand_500.cfg -d $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/ > vallog 2>&1 &
        ./$RS -a $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/asn_2_id.cfg -i $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/as_ips.cfg -f $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/peers_uni_500_020.cfg -r $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/prefer_rand_500.cfg -d $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/ &
        #./$RS -a $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/asn_2_id.cfg -i $INSTALL_ROOT/examples/$EXAMPLE_NAME/$RIB_NAME/as_ips.cfg -f $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/peers_uni_500_020.cfg -r $INSTALL_ROOT/examples/$EXAMPLE_NAME/bgp_policies/prefer_rand_500.cfg &
        while [ ! -f sig ]
        do
            sleep 2
        done
        rm sig
		#fi
	
		# Start Participant controller
        AS_NUM_RANGE=`expr $AS_NUM - 1`
        for i in $(seq 0 $AS_NUM_RANGE)
		do
			echo "Starting Participant $i Controller..."
			cd $INSTALL_ROOT/pctrl-sgdx; python participant_controller.py $EXAMPLE_NAME/$RIB_NAME/ $i &
            while [ ! -f $INSTALL_ROOT/sxrs/sig ]
            do
                sleep 0.01
            done
            rm $INSTALL_ROOT/sxrs/sig
		done
        sleep 3

		echo "Starting XBGP..."
		cd $INSTALL_ROOT/xbgp; ./xbgp.py 2 localhost 6000 $UPDATE_FILE $RATE $MODE --seperate_prefix &
	done
done
