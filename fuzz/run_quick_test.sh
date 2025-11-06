#!/bin/bash
# Quick fuzz test - runs new targets for 10 seconds each
# Useful for quick validation before longer fuzzing runs

set -e

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}Running quick fuzz test on new targets (10s each)${NC}\n"

# Test the new signature targets
NEW_TARGETS=(
    "signature_deserialization"
    "sign"
    "verify"
    "signing_keypair_deserialization"
    "signing_public_key_deserialization"
    "online_ciphertext_header_deserialization"
    "online_encrypt_symmetric"
    "online_encrypt_asymmetric"
    "online_decrypt_symmetric"
    "online_decrypt_asymmetric"
    "mix_key_exchange"
    "derive_key_argon2"
    "scrypt_simple"
)

for target in "${NEW_TARGETS[@]}"; do
    echo -e "${YELLOW}Testing: ${target}${NC}"
    timeout 10s cargo fuzz run "${target}" -- -max_total_time=10 || true
    echo ""
done

echo -e "${CYAN}Quick test complete!${NC}"
echo "For full fuzzing, run: ./run_all_fuzz_tests.sh"
