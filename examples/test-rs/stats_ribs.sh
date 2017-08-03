#! /bin/bash

Entry=0

for f in $1rib_*
do
    Entry=$((Entry + $(./stats.py $f)))
done

echo $Entry
