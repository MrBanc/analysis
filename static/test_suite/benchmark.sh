#!/bin/bash
basic="basic_tests"
glibc="glibc_tests"
build="build"
results="$PWD/results"

array_flags=("O0" "O1" "O2" "O3" "Os" "Og")

die() {
    echo "$@" >&2
    exit 1
}

build_binaries() {

    dir="$1"
    rm -rf "${dir:?}/${build}" "${dir}/${build}_all" &> "/dev/null"
    mkdir -p "${dir}/${build}" &> "/dev/null"|| die "mkdir failed"
    cd "${dir}" || die "cd failed"
    echo "Generating ${dir} tests..."
    for flag in "${array_flags[@]}"
    do
        make PARAM="-$flag" &> "/dev/null" || die "make failed"
        mkdir -p "${build}_all/$flag" || die "mkdir failed"
        if [ "$dir" == "$basic" ]; then
            cp ${build}/* "${build}_all/$flag" || die "cp failed"
        else
            cp main "${build}_all/$flag" || die "cp failed"
        fi
        make clean &> "/dev/null"
    done
    rm -rf "${build}" &> "/dev/null"
    cd .. || die "cd failed"
}

iterate_output(){
    dir="$1"
    binary="$2"

    for file in "${results}_${binary}/${dir}"/*; do
        compare_output "$file" "${results}_static_analyser/${dir}/$(basename $file)"
    done
}

compare_output(){
    f1="$1"
    f2="$2"
    sort "$f1" | uniq > /tmp/sorted_f1
    sort "$f2" | uniq > /tmp/sorted_f2

    comm -23 /tmp/sorted_f1 /tmp/sorted_f2 > /tmp/f1_not_in_f2

    a=$(wc -l /tmp/f1_not_in_f2|awk '{ print $1 }')
    b=$(wc -l /tmp/sorted_f2|awk '{ print $1 }')

    echo -n "$(basename $f1): "
    if [ -s /tmp/f1_not_in_f2 ]; then
        echo -n "[MISSING $a/$b] "
        awk '{print}' ORS=' ' < /tmp/f1_not_in_f2
    else
        echo -n "[OK $a/$b] "
    fi
    echo " "
    rm /tmp/sorted_f1 /tmp/sorted_f2 /tmp/f1_not_in_f2
}

benchmark_binaries(){

    dir="$1"
    binary="$2"
    cd "${dir}" || die "cd failed"
    rm -rf "${results}_${binary}/${dir}" &> "/dev/null"
    mkdir -p "${results}_${binary}/${dir}" || die "mkdir failed"
    echo "Benchmarking ${dir} with ${binary}..."
    for flag in "${array_flags[@]}"; do
        for file in "${build}_all/$flag"/*; do
            if [ "$binary" == "static_analyser" ]; then
                timeout 60 python3 ../../static_analyser.py -s ../../syscalls_map --app "./$file" --show-warnings f -v f |awk '{ print $1}' | sort > "${results}_${binary}/${dir}/${flag}_$(basename $file).txt"
            else
                #TODO: Add $4, and sort -n to have the number of occurences
                "${binary}" -c -f "./$file" 2>&1 >/dev/null | awk '$NF != "total" {print $NF}' | grep -v -e '^--' -e '^usecs/call' -e '^attached' -e '^syscall'  -e '^function'| sed '/^$/d' | sort > "${results}_${binary}/${dir}/${flag}_$(basename $file).txt"
            fi
        done
    done
    cd .. || die "cd failed"
}

if [ ! -d "${basic}/${build}_all" ]; then
    build_binaries "${basic}"
fi

if [ ! -d "${glibc}/${build}_all" ]; then
    build_binaries "${glibc}"
fi

mkdir -p "${results}" || die "mkdir failed"

directories=("basic_tests" "glibc_tests")
binaries=("static_analyser" "strace" "ltrace")

for dir in "${directories[@]}"; do
    for binary in "${binaries[@]}"; do
        benchmark_binaries "${dir}" "${binary}"
    done
    iterate_output "${dir}" "strace" > "${results}_all/${dir}_strace.txt"
done