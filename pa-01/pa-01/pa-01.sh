#Script to run pa-01

rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.decr
rm -f bunny.mp4
ln -s ../bunny.mp4 bunny.mp4

echo "==========================================="
echo "Compiling source code"
    gcc genKey.c -o genKey -lcrypto
    gcc amal/amal.c myCrypto.c -o amal/amal -lcrypto
    gcc basim/basim.c myCrypto.c -o basim/basim -lcrypto
    gcc wrappers.c dispatcher.c -o dispatcher

./genKey
echo 
echo "Symmetric key information:"
hexdump -C key.bin

echo
echo "IV information:"
hexdump -C iv.bin

echo 
echo "Providing Basim and Amal with IV and key"
cd amal
    rm -f key.bin iv.bin
    ln -s ../key.bin key.bin
    ln -s ../iv.bin iv.bin
    cd ../
cd basim
    rm -f key.bin iv.bin
    ln -s ../key.bin key.bin
    ln -s ../iv.bin iv.bin
    cd ../

echo "=========================================="
echo "Starting dispatcher"
./dispatcher

echo
echo "========= Amal's Log ========="
cat amal/logAmal.txt

echo
echo "======== Basim's Log ========"
cat basim/logBasim.txt

echo "========================================="
echo "Comparing encrypted and decrypted file"
diff -s bunny.mp4 bunny.decr
echo
