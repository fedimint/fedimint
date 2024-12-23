# for i in {1..10}; do
#   RUST_BACKTRACE=1 \
#   FM_DEVIMINT_DISABLE_MODULE_LNV2=1 \
#   just test-upgrades v0.4.0 current &>> results.log
#   echo "sleeping to give daemons time to shutdown" &>> results.log
#   sleep 10
# done


# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.3.3 current &> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.3.4-rc.1 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.4.0 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.4.1 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.4.2 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.4.3 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.4.4 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.5.0 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.3.3 v0.4.0 current &>> results.log
# sleep 60
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 TEST_KINDS=fedimint-cli,gateway just test-upgrades v0.3.1 current &>> results.log

rm results.log

start=$(date +%s)  # Record start time in nanoseconds

# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.3.4-rc.1 current &>> results.log
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.4.4 current &>> results.log
# FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades v0.5.0 current &>> results.log

FM_DEVIMINT_DISABLE_MODULE_LNV2=1 just test-upgrades "v0.3.4-rc.1 current, v0.4.4 current, v0.5.0 current" &> results.log

end=$(date +%s)    # Record end time in nanoseconds
runtime=$((end - start)) # Calculate the difference
echo "Runtime: $runtime seconds" >> results.log
