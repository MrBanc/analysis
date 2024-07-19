#!/bin/bash

# script working directory
SWD=$(dirname $(realpath "$0"))

basic="basic_tests"
glibc="glibc_tests"
build="build"
results="$SWD/results"

array_flags=("O0" "O1" "O2" "O3" "Os" "Og")

glibc_tests=("string" "fdopen" "search_hsearch" "fnmatch" "fscanf" "popen" "socket" "spawn" "qsort" "time" "sscanf" "snprintf" "swprintf" "stat" "string" "strtol" "ungetc" "wcstol" "fwscanf" "basename" "dirname" "memstream" "mbc" "setjmp" "sem" "pthread" "random" "strtod" "crypt" "tgmath" "utime" "wcsstr" "env")

debug=false

die() {
    echo "$@" >&2
    exit 1
}

build_binaries() {
    dir="$1"
    rm -rf "${dir:?}/${build}" "${dir}/${build}_all" &> "/dev/null"
    mkdir -p "${dir:?}/${build}" &> "/dev/null"
    if [ $? -ne 0 ]; then
        die "mkdir failed"
    fi
    cd "${dir}" || die "cd failed"
    echo "Generating ${dir} tests..."
    for flag in "${array_flags[@]}"
    do
        make PARAM="-$flag" &> "/dev/null" || die "make failed"
        mkdir -p "${build}_all/$flag" || die "mkdir failed"
        if [ "$dir" == "$basic" ]; then
            cp -r ${build}/* "${build}_all/$flag" || die "cp failed"
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
            if [ "$(basename $file)" == "lib" ]; then
                continue
            fi
            if [ "$binary" == "static_analyser" ]; then
                if [[ "$file" =~ /test[0-9]*shrLib ]]; then
                    LD_LIBRARY_PATH=./${build}_all/${flag}/lib timeout 600 python3 ../../static_analyser.py -s ../../syscalls_map --app "./$file" --show-warnings f --show-errors f -v f --analyse-linker t --user-input Y --skip-data t --search_raw_data t | awk '{ print $1}' | sort > "${results}_${binary}/${dir}/${flag}_$(basename $file).txt"
                else
                    timeout 600 python3 ../../static_analyser.py -s ../../syscalls_map --app "./$file" --show-warnings f --show-errors f -v f --analyse-linker t --user-input Y --skip-data t --search_raw_data t | awk '{ print $1}' | sort > "${results}_${binary}/${dir}/${flag}_$(basename $file).txt"
                fi
                if [ "$debug" == "true" ] && [ "$dir" == "$glibc" ]; then
                    for t in "${glibc_tests[@]}"; do
                        cp "${results}_${binary}/${dir}/${flag}_$(basename $file).txt" "${results}_${binary}/${dir}/${flag}_$(basename $file)_${t}.txt" 
                    done
                    rm "${results}_${binary}/${dir}/${flag}_$(basename $file).txt" 
                fi
            elif [ "$debug" == "true" ] && [ "$dir" == "$glibc" ]; then
                # These result are not fair as the static analyser will only do a single run for all these tests. It is only for a debugging purpose
                for t in "${glibc_tests[@]}"; do
                    "${binary}" -c -f -o temporary_trace_result "./$file" $t &> temporary_file_result
                    cat temporary_trace_result | awk '$NF != "total" {print $NF}' | grep -v -e '^--' -e '^usecs/call' -e '^attached' -e '^syscall$'  -e '^function$'| sed '/^$/d' | sort > "${results}_${binary}/${dir}/${flag}_$(basename $file)_${t}.txt"
                    rm temporary_file_result temporary_trace_result
                done
            else
                # TODO: Add $4, and sort -n to have the number of occurences
                # use temporary files because /dev/null would yeild an ioctl
                # syscall and errors from the $file binary could be mixed with
                # the $binary output
                if [[ "$file" =~ /test[0-9]*shrLib ]]; then
                    LD_LIBRARY_PATH=./${build}_all/${flag}/lib "${binary}" -c -f -o temporary_trace_result "./$file" &> temporary_file_result
                    echo "LD_LIBRARY_PATH=./${build}_all/${flag}/lib \"${binary}\" -c -f -o temporary_trace_result \"./$file\" &> temporary_file_result"
                    exit
                else
                    "${binary}" -c -f -o temporary_trace_result "./$file" &> temporary_file_result
                fi
                cat temporary_trace_result | awk '$NF != "total" {print $NF}' | grep -v -e '^--' -e '^usecs/call' -e '^attached' -e '^syscall$'  -e '^function$'| sed '/^$/d' | sort > "${results}_${binary}/${dir}/${flag}_$(basename $file).txt"
                rm temporary_file_result temporary_trace_result
            fi
        done
    done
    cd .. || die "cd failed"
}






# ---------------------------- MAIN ----------------------------






if [ $# -eq 0 ]; then
    echo "No arguments supplied, run all? [y/n]"
    read -r answer
    if [ "$answer" == "y" ]; then
        set -- "-a"
    else
        echo "Exiting..."
        exit 0
    fi
fi

if [ "$1" == "-h" ]; then
    echo "Usage: $0 [-b] [-r] [-i] [-c] [-h] [-a]"
    echo "  -b: build binaries"
    echo "  -r: run benchmarks"
    echo "  -i: iterate output"
    echo "  -c: clean"
    echo "  -h: help"
    echo "  -a: all"
    exit 0
fi

if [ "$1" == "-c" ]; then
    rm -rf "${basic}/${build}" "${basic}/${build}_all" "${glibc}/${build}" "${glibc}/${build}_all" "${results}" "${results}_*" &> "/dev/null"
    exit 0
fi

if [ "$1" == "-a" ] || [ "$1" == "-b" ]; then
    rm -rf "${basic}/${build}" "${basic}/${build}_all" "${glibc}/${build}" "${glibc}/${build}_all" &> "/dev/null"
    build_binaries "${basic}"
    build_binaries "${glibc}"
fi

if [ "$1" == "-a" ] || [ "$1" == "-r" ]; then
    mkdir -p "${results}" || die "mkdir failed"

    directories=("basic_tests" "glibc_tests")
    binaries=("static_analyser" "strace" "ltrace")

    for dir in "${directories[@]}"; do
        for binary in "${binaries[@]}"; do
            benchmark_binaries "${dir}" "${binary}"
        done
        iterate_output "${dir}" "strace" > "${results}_all/${dir}_strace.txt"
    done
fi

if [ "$1" == "-i" ]; then
    directories=("basic_tests" "glibc_tests")
    for dir in "${directories[@]}"; do
        iterate_output "${dir}" "strace" > "${results}_all/${dir}_strace.txt"
    done
fi
