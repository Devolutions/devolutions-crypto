# Setup a wsl ubuntu 24.04 to compile devolutions crypto kotlin
sudo apt update
sudo apt install unzip make gcc-multilib software-properties-common -y
sudo apt install gcc-aarch64-linux-gnu -y

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

. "$HOME/.cargo/env"

cargo --version

EXPORT_LINE='export PATH="$HOME/.cargo/bin:$PATH"'
echo "$EXPORT_LINE" >> "$HOME/.bashrc"

rustup target add x86_64-unknown-linux-gnu
rustup target add i686-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu

# install kotlin
sudo snap install --classic kotlin

# install ktlint
sudo snap install ktlint --edge --devmode

echo "$ENV_VARS" >> "$HOME/.bashrc"