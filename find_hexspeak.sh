#!/bin/bash

# Hexspeak Magic Number Search Script
# Based on notable magic numbers from https://en.wikipedia.org/wiki/Hexspeak
# Ordered from shortest to longest

echo "🔮✨ Hexspeak Magic Number Hunt! ✨🔮"
echo "Searching for notable magic numbers from Wikipedia..."
echo "=========================================================="

cd "$(dirname "$0")"

# Function to search for a pattern
search_pattern() {
    local pattern=$1
    local description=$2
    
    echo ""
    echo "🔍 Searching for: $pattern ⚫️ $description"
    echo "⏱️  Pattern length: ${#pattern} characters"
    
    # Run the search
    if ./target/release/meshcore-keygen "$pattern"; then
        echo "✅ Found $pattern!"
    else
        echo "❌ Search failed for $pattern"
    fi
}

# Search each pattern
search_pattern "4B1D" "forbid - password in calibration consoles"
search_pattern "F1AC" "FLAC - Free Lossless Audio Codec format tag"

search_pattern "00BAB10C" "uber block - ZFS uberblock magic number"
search_pattern "0B00B135" "boobies - Microsoft Hyper-V user id"
search_pattern "0D15EA5E" "zero disease - GameCube/Wii regular boot flag"
search_pattern "1BADB002" "1 bad boot - Multiboot header magic number"
search_pattern "50FFC001" "soff cool - Macintosh debug value"
search_pattern "8BADF00D" "ate bad food - Apple iOS crash reports"
search_pattern "ABADBABE" "a bad babe - Windows 7 debugger breakpoint"
search_pattern "B105F00D" "BIOS food - ARM PrimeCell component ID"
search_pattern "B16B00B5" "big boobs - Microsoft Hyper-V guest signature"
search_pattern "BAAAAAAD" "baaaaaad - Apple iOS stackshot indicator"

search_pattern "BAADF00D" "bad food - Microsoft LocalAlloc debug heap"
search_pattern "BAD22222" "bad too repeatedly - Apple iOS VoIP termination"
search_pattern "BADDCAFE" "bad cafe - Libumem uninitialized memory"
search_pattern "BEEFBABE" "beef babe - Frogger stack buffer overflow detection"
search_pattern "C00010FF" "cool off - Apple iOS thermal event"
search_pattern "CAFEBABE" "cafe babe - Java bytecode, Mach-O, Plan 9"
search_pattern "CAFED00D" "cafe dude - Java pack200 compression"
search_pattern "CEFAEDFE" "face feed - Mach-O flat object files"
search_pattern "DABBAD00" "dabba doo - computer security blog name"
search_pattern "DEAD2BAD" "dead too bad - Sequent Dynix/ptx uninitialized memory"

search_pattern "DEADBAAD" "dead bad - Android libc native heap corruption"
search_pattern "DEADBABE" "dead babe - IBM Jikes RVM stack sanity check"
search_pattern "DEADBEAF" "dead beaf - Jazz Jackrabbit 2 tileset signature"
search_pattern "DEADBEEF" "dead beef - most famous, software crash/deadlock"
search_pattern "DEADC0DE" "dead code - OpenWrt firmware jffs2 marker"
search_pattern "DEADDEAD" "dead dead - Windows Blue Screen of Death"
search_pattern "DEADD00D" "dead dude - Android Dalvik VM abort"
search_pattern "DEADFA11" "dead fall - Apple iOS force quit"
search_pattern "DEAD10CC" "dead lock - Apple iOS system resource hold"
search_pattern "DEADFEED" "dead feed - Apple iOS service spawn timeout"

search_pattern "DECAFBAD" "decaf bad - recognizable magic number"
search_pattern "DEFEC8ED" "defecated - OpenSolaris core dumps"
search_pattern "D0D0CACA" "doo-doo caca - Nvidia Tegra X1 GPIO values"
search_pattern "E011CFD0" "docfile0 - Microsoft Office files"
search_pattern "F0CACC1A" "focaccia - highest scrabble score hexspeak"
search_pattern "FACEFEED" "face feed - Alpha servers Windows NT HAL"
search_pattern "FBADBEED" "bad beef - WebKit/Blink unrecoverable errors"
search_pattern "FEE1DEAD" "feel dead - Linux reboot system call"
search_pattern "FEEDBABE" "feed babe - OpenRG flash partition descriptor"
search_pattern "FEEDC0DE" "feed code - OS-9 RAM initialization pattern"
search_pattern "FFBADD11" "bad DLL - Windows internal usage"
search_pattern "F00DBABE" "food babe - Ledger Nano wallet exploit"

search_pattern "ACE0FBA5E" "Ace of Base - Swedish pop band reference"

search_pattern "FEEDFACECAFEBEEF" "feed face cafe beef - NXP controller rescue password"

echo ""
echo "🎉 Hexspeak hunt complete! 🎉"
echo "All patterns have been searched."
echo ""
echo "💡 Tip: Check meshcore-keys.txt for all the found keys!"
echo "🗑️  Remember to securely delete when done: ./meshcore-keygen --delete"
