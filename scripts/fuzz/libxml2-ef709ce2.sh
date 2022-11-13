if [ ! -d "./libxml2_ef709ce2" ]; then
    git clone https://gitlab.gnome.org/GNOME/libxml2.git libxml2_ef709ce2
fi
if [ -d "./libxml2_ef709ce2" ]; then
    cd libxml2_ef709ce2; #git checkout -f ef709ce2
    if [ -d "./obj-aflgo" ]; then
        cd obj-aflgo;rm -rf out
        export TMP_DIR=$PWD/temp
        $AFLGO/afl-fuzz -m none -z exp -U -D $TMP_DIR -c 45m -t 10000 -i in -o out ./xmllint --valid --recover @@
    fi
    mkdir obj-aflgo; mkdir obj-aflgo/temp
    export SUBJECT=$PWD; export TMP_DIR=$PWD/obj-aflgo/temp
    export SVF_DIR=$AFLGO/SVF/Release-build/bin
    export CC=$AFLGO/afl-clang-fast; export CXX=$AFLGO/afl-clang-fast++
    export LDFLAGS=-lpthread
    export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
    git diff -U0 HEAD^ HEAD > $TMP_DIR/commit.diff
    wget https://raw.githubusercontent.com/jay/showlinenum/develop/showlinenum.awk
    chmod +x showlinenum.awk
    mv showlinenum.awk $TMP_DIR
    cat $TMP_DIR/commit.diff |  $TMP_DIR/showlinenum.awk show_header=0 path=1 | grep -e "\.[ch]:[0-9]*:+" -e "\.cpp:[0-9]*:+" -e "\.cc:[0-9]*:+" | cut -d+ -f1 | rev | cut -c2- | rev > $TMP_DIR/BBtargets.txt
    ./autogen.sh; make distclean
    cd obj-aflgo; CFLAGS="$ADDITIONAL" CXXFLAGS="$ADDITIONAL" ../configure --disable-shared --prefix=`pwd`
    make clean; make -j4

    $SVF_DIR/wpa --print-fp --ander $SUBJECT/xmllint.0.0.preopt.bc >> $TMP_DIR/indirect.txt
    $AFLGO/scripts/ex_incallsite.sh $TMP_DIR/indirect.txt $TMP_DIR

    cat $TMP_DIR/BBnames.txt  | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
    cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
    cat $TMP_DIR/BBinCalls.txt | sort | uniq > $TMP_DIR/BBinCalls2.txt && mv $TMP_DIR/BBinCalls2.txt $TMP_DIR/BBinCalls.txt

    $AFLGO/scripts/gen_distance_fast.py -p $SUBJECT $TMP_DIR xmllint
    # CFLAGS="-distance=$TMP_DIR/distance.cfg.txt" CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt" ../configure --disable-shared --prefix=`pwd`
    # make clean; make -j4
    mkdir in; cp $SUBJECT/test/dtd* in; cp $SUBJECT/test/dtds/* in
    $AFLGO/afl-fuzz -m none -z exp -U -D $TMP_DIR -c 45m -t 10000 -i in -o out ./xmllint --valid --recover @@
fi
