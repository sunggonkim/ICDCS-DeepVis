#!/bin/bash
sudo apt-get update
sudo apt-get install -y git build-essential linux-headers-$(uname -r)

mkdir -p ~/rootkits
cd ~/rootkits

# Diamorphine
if [ ! -d "Diamorphine" ]; then
    echo "Cloning Diamorphine..."
    git clone https://github.com/m0nad/Diamorphine.git
    cd Diamorphine
    make
    cd ..
fi

# Reptile
if [ ! -d "Reptile" ]; then
    echo "Cloning Reptile..."
    git clone https://github.com/f0rb1dd3n/Reptile.git
    cd Reptile
    # Reptile build might be interactive or complex, try simple make
    make
    cd ..
fi

echo "Rootkits setup complete."
ls -R ~/rootkits
