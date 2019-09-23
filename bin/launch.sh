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
        if [ -z "${!v}" ]
        then
            echo "ERROR: undefined config var: $v" 2>&1
            exit 1
        fi
    done
}

function eval_vars()
{
    for var in $@
    do
        echo $var=${!var}
    done
}

function set_default()
{
    local name="$1"
    local val="$2"
    # Check for set/unset not emptiness to let empty carry meaning
    if [ ! "${!name+_}" ]
    then
        declare -g "$name=$val"
    fi
}

function dump_dict()
{
    local dict=$1
    # Appears to be no way to get keys from indirectly referenced assoc array
    # without eval (in Bash <4.3, which doesn't have named references).
    for key in $(eval "echo \${!$dict[@]}")
    do
        local var=${dict}[$key]
        echo "[$key]=${!var}"
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
    local oob_size=$3
    local pages_per_block=$4
    # TODO: -1 because qemu-nand-creator adds an extra block?
    echo $(( size / (pages_per_block * (page_size + oob_size)) - 1))
}

create_nand_image()
{
    local file=$1
    local size=$2
    local page_size=$3
    local pages_per_block=$4
    local oob_size=$5
    local ecc_size=$6
    local blocks="$(nand_blocks "$size" "$page_size" "$oob_size" "$pages_per_block")"
    run qemu-nand-creator "$page_size" "$oob_size" "$pages_per_block" "$blocks" "$ecc_size" 1 "$file"
}

# Params for off chip mem (passed in dictionary):
#   src: path to file from which to init mem image (none = create blank)
#   run: path to file that will persist the content across runs
#   overwrite: whether to copy from source file on each run
#  size: size of memory storage array in bytes
# (other): more image parameters (see each function)

function init_smc_nand_img()
{
    local P=$1 # name of assoc array with properties of mem image

    check_vars $P[run] $P[size] $P[page] $P[ppb] $P[oob] $P[ecc]

    # Temporary copy into a local assoc array for more convenient addressing
    declare -A "props=($(dump_dict ${P}))"

    create_if_absent "${props[run]}" "${props[src]}" "${props[overwrite]}" \
        create_nand_image "$(numfmt --from=iec "${props[size]}")" \
            "${props[page]}" "${props[ppb]}" "${props[oob]}" "${props[ecc]}"
}

function init_smc_sram_img()
{
    local P=$1 # name of assoc array with properties of mem image

    check_vars $P[run] $P[size]

    # Temporary copy into a local assoc array for more convenient addressing
    declare -A "props=($(dump_dict $P))"

    create_if_absent "${props[run]}" "${props[src]}" "${props[overwrite]}" \
        create_sram_image "$(numfmt --from=iec "${props[size]}")"
}
