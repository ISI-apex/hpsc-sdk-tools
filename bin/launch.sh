# Functionality common across launch-* scripts for launching HW emulators
# This script should be sourced, not run directly.

run() {
    echo "$@"
    "$@"
}

function check_vars()
{
    for v in $@
    do
        if [ -z "\$$v" ]
        then
            echo "ERROR: undefined config var: $v" 2>&1
            exit 1
        fi
    done
}

function source_if_exists()
{
    if [ -f "$1" ]
    then
        echo "Loading env from: $1"
        source "$1"
    fi
}

parse_addr() {
    echo "$1" | sed 's/_//g'
}
hex() {
    printf "0x%x" "$1"
}

extract_word() {
    IDX=$1
    shift
    local i=0
    for w in "$@"
    do
        if [ $i -eq $IDX ]
        then
            echo $w
            return
        fi
        i=$(($i + 1))
    done
}

create_if_absent()
{
    local dest=$1
    local src=$2
    local overwrite=$3
    local creator=$4
    shift 4
    if [[ ! -f "$dest" || "$overwrite" -eq 1 ]]
    then
        if [ -f "$src" ]
        then
            echo "Overwriting memory image..."
            run cp "$src" "$dest"
        else
            echo "Creating memory image..."
            $creator "$dest" "$@"
        fi
    else
        echo "Using existing memory image: $dest"
    fi
}

function create_sram_image()
{
    run sram-image-utils create "$1" "$2"
    run sram-image-utils show "$1"
}

function nand_blocks()
{
    local size=$1
    local page_size=$2
    local pages_per_block=$3
    echo $(( size / (pages_per_block * page_size) ))
}

create_nand_image()
{
    local file=$1
    local size=$2
    local page_size=$3
    local pages_per_block=$4
    local oob_size=$5
    local ecc_size=$6
    local blocks="$(nand_blocks "$size" "$page_size" "$pages_per_block")"
    run qemu-nand-creator "$page_size" "$oob_size" "$pages_per_block" "$blocks" "$ecc_size" 1 "$file"
}
