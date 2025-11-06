#!/bin/bash
# Run all fuzz tests for 60 seconds each
# Usage: ./run_all_fuzz_tests.sh [duration_in_seconds]
# Example: ./run_all_fuzz_tests.sh 120  (runs each test for 2 minutes)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default duration per test (60 seconds)
DURATION=${1:-60}
CORPUS_DIR="corpus"
ARTIFACTS_DIR="artifacts"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Devolutions Crypto Fuzz Test Suite${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "Duration per test: ${YELLOW}${DURATION}s${NC}"
echo -e "Start time: ${BLUE}$(date)${NC}\n"

# Check if we're in the fuzz directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "fuzz_targets" ]]; then
    echo -e "${RED}Error: Must be run from the fuzz directory${NC}"
    echo "Please run: cd fuzz && ./run_all_fuzz_tests.sh"
    exit 1
fi

# Check if cargo-fuzz is installed
if ! command -v cargo-fuzz &> /dev/null; then
    echo -e "${RED}Error: cargo-fuzz is not installed${NC}"
    echo -e "Install with: ${YELLOW}cargo install cargo-fuzz${NC}"
    exit 1
fi

# Check if nightly toolchain is available
if ! rustup toolchain list | grep -q nightly; then
    echo -e "${YELLOW}Warning: Nightly toolchain not found. Installing...${NC}"
    rustup install nightly
    rustup default nightly
fi

# Get list of all fuzz targets
echo -e "${BLUE}Discovering fuzz targets...${NC}"
TARGETS=($(cargo fuzz list 2>/dev/null | grep -v "^warning:"))
TOTAL_TARGETS=${#TARGETS[@]}

echo -e "Found ${GREEN}${TOTAL_TARGETS}${NC} fuzz targets\n"

# Create directories for results
mkdir -p "${CORPUS_DIR}"
mkdir -p "${ARTIFACTS_DIR}"

# Track statistics
PASSED=0
FAILED=0
TOTAL_TIME=0
START_TIMESTAMP=$(date +%s)

# Array to store failed tests
declare -a FAILED_TESTS

# Function to run a single fuzz test
run_fuzz_test() {
    local target=$1
    local num=$2
    local total=$3

    echo -e "${CYAN}[${num}/${total}]${NC} Running ${YELLOW}${target}${NC}..."

    local start_time=$(date +%s)
    local log_file="fuzz_${target}_$(date +%Y%m%d_%H%M%S).log"

    # Run the fuzzer
    if timeout ${DURATION}s cargo fuzz run "${target}" -- \
        -max_total_time=${DURATION} \
        -print_final_stats=1 \
        -rss_limit_mb=2048 \
        > "${log_file}" 2>&1; then

        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))

        # Check if any crashes were found
        if [[ -d "artifacts/${target}" ]] && [[ -n "$(ls -A artifacts/${target} 2>/dev/null)" ]]; then
            echo -e "  ${RED}✗ FAILED${NC} - Crashes found! (${elapsed}s)"
            echo -e "    Artifacts saved in: ${YELLOW}artifacts/${target}/${NC}"
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("${target}")
        else
            echo -e "  ${GREEN}✓ PASSED${NC} (${elapsed}s)"
            PASSED=$((PASSED + 1))
        fi

        # Extract and display stats if available
        if grep -q "stat::" "${log_file}"; then
            local execs=$(grep "stat::number_of_executed_units:" "${log_file}" | tail -1 | awk '{print $2}')
            local coverage=$(grep "stat::average_exec_per_sec:" "${log_file}" | tail -1 | awk '{print $2}')
            [[ -n "${execs}" ]] && echo -e "    Executions: ${execs}"
            [[ -n "${coverage}" ]] && echo -e "    Exec/sec: ${coverage}"
        fi
    else
        local exit_code=$?
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))

        if [[ ${exit_code} -eq 124 ]]; then
            # Timeout is expected
            echo -e "  ${GREEN}✓ PASSED${NC} (${elapsed}s, timeout reached)"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}✗ FAILED${NC} - Error code: ${exit_code} (${elapsed}s)"
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("${target}")
        fi
    fi

    # Clean up log file if no issues
    if [[ ${FAILED} -eq 0 ]] || [[ ! " ${FAILED_TESTS[@]} " =~ " ${target} " ]]; then
        rm -f "${log_file}"
    else
        echo -e "    Log saved: ${YELLOW}${log_file}${NC}"
    fi

    TOTAL_TIME=$((TOTAL_TIME + elapsed))
    echo ""
}

# Run all fuzz tests
for i in "${!TARGETS[@]}"; do
    run_fuzz_test "${TARGETS[$i]}" $((i + 1)) ${TOTAL_TARGETS}
done

# Calculate total elapsed time
END_TIMESTAMP=$(date +%s)
TOTAL_ELAPSED=$((END_TIMESTAMP - START_TIMESTAMP))
HOURS=$((TOTAL_ELAPSED / 3600))
MINUTES=$(((TOTAL_ELAPSED % 3600) / 60))
SECONDS=$((TOTAL_ELAPSED % 60))

# Print summary
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Fuzzing Summary${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "Total targets: ${BLUE}${TOTAL_TARGETS}${NC}"
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo -e "Total time: ${YELLOW}${HOURS}h ${MINUTES}m ${SECONDS}s${NC}"
echo -e "End time: ${BLUE}$(date)${NC}"

# Show failed tests if any
if [[ ${FAILED} -gt 0 ]]; then
    echo -e "\n${RED}Failed tests:${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "  - ${test}"
    done
    echo -e "\nCheck ${YELLOW}artifacts/${NC} directory for crash details"
    exit 1
else
    echo -e "\n${GREEN}All fuzz tests passed! ✓${NC}"
    exit 0
fi
