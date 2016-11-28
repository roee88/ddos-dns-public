cut -d , -f 3 top-50k-ns-ip.csv >top-50k-ip.csv
awk " !x[$0]++" top-50k-ip.csv >top-50k-ip.nodup.csv