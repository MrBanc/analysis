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

benchmark_binaries(){

    dir="$1"
    binary="$2"
    cd "${dir}" || die "cd failed"
    rm -rf "${results}_${binary}/${dir}" &> "/dev/null"
    mkdir -p "${results}_${binary}/${dir}" || die "mkdir failed"
    echo "Benchmarking ${dir} tests..."
    for flag in "${array_flags[@]}"; do
        for file in "${build}_all/$flag"/*; do 
            "${binary}" -c -f "./$file" 2>&1 >/dev/null | awk '$NF != "total" {print $4,$NF}' | grep -v -e '^--' -e '^usecs/call' -e '^attached'| sed '/^$/d' | sort -n > "${results}_${binary}/${dir}/${flag}_$(basename $file).txt"
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

benchmark_binaries "${basic}" "strace" && benchmark_binaries "${basic}" "ltrace" 

benchmark_binaries "${glibc}" "strace" && benchmark_binaries "${glibc}" "ltrace"