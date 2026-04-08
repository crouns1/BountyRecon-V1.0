#!/usr/bin/env bash
# ============================================================================
# setup.sh — Dependency installer for BountyRecon v2.0 Framework
# Installs 40+ recon/exploit/misc tools on Debian/Kali Linux
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }
log_section() { echo -e "\n${CYAN}═══ $1 ═══${NC}\n"; }

# ── Go-based tools ──────────────────────────────────────────────────────────
GO_TOOLS=(
    # Recon
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    # Exploit
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    # Misc
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/LukaSikworx/subzy@latest"
    "github.com/haccer/subjack@latest"
    "github.com/hakluke/hakoriginfinder@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/tomnomnom/hurl@latest"
)

# ── System packages ─────────────────────────────────────────────────────────
SYSTEM_PACKAGES=(
    "python3" "python3-pip" "python3-venv" "git" "curl" "wget" "jq"
    "dnsutils" "libpcap-dev" "masscan" "nmap" "nikto" "whatweb"
    "wpscan" "sqlmap" "commix" "hydra"
)

# ── Python/pip tools ────────────────────────────────────────────────────────
PIP_TOOLS=(
    "arjun" "paramspider" "uro" "wafw00f"
    "corsy" "Oralyzer" "dirsearch"
)

# ── Git-cloned tools ────────────────────────────────────────────────────────
declare -A GIT_REPOS=(
    ["SecretFinder"]="https://github.com/m4ll0k/SecretFinder.git"
    ["smuggler"]="https://github.com/defparam/smuggler.git"
    ["h2csmuggler"]="https://github.com/BishopFox/h2csmuggler.git"
    ["SSTImap"]="https://github.com/vladko312/SSTImap.git"
    ["toxicache"]="https://github.com/xhzeem/toxicache.git"
    ["S3Scanner"]="https://github.com/sa7mon/S3Scanner.git"
    ["nomore403"]="https://github.com/devploit/nomore403.git"
    ["graphw00f"]="https://github.com/dolevf/graphw00f.git"
    ["clairvoyance"]="https://github.com/nikitastupin/clairvoyance.git"
    ["headi"]="https://github.com/mlcsec/headi.git"
    ["jwt_tool"]="https://github.com/ticarpi/jwt_tool.git"
    ["git-dumper"]="https://github.com/arthaud/git-dumper.git"
    ["CloudBrute"]="https://github.com/0xsha/CloudBrute.git"
    ["dnsReaper"]="https://github.com/punk-security/dnsReaper.git"
    ["OpenRedireX"]="https://github.com/devanshbatham/OpenRedireX.git"
    ["CRLFsuite"]="https://github.com/Nefcore/CRLFsuite.git"
    ["kxss"]="https://github.com/Emoe/kxss.git"
    ["nosqli"]="https://github.com/Charlie-belmer/nosqli.git"
    ["x8"]="https://github.com/Sh1Yo/x8.git"
    ["waymore"]="https://github.com/xnl-h4ck3r/waymore.git"
    ["urlfinder"]="https://github.com/projectdiscovery/urlfinder.git"
    ["ghauri"]="https://github.com/r0oth3x49/ghauri.git"
    ["gotator"]="https://github.com/Josue87/gotator.git"
    ["dnsgen"]="https://github.com/ProjectAnte/dnsgen.git"
    ["forbidden-buster"]="https://github.com/Sn1r/forbidden-buster.git"
    ["noseyparker"]="https://github.com/praetorian-inc/noseyparker.git"
)

TOOLS_DIR="$HOME/tools"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_warn "Not running as root. Some installations may fail."
        log_warn "Re-run with: sudo bash setup.sh"
    fi
}

install_system_packages() {
    log_section "System Packages"
    sudo apt-get update -qq

    for pkg in "${SYSTEM_PACKAGES[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            log_info "$pkg ✓"
        else
            log_warn "Installing $pkg..."
            sudo apt-get install -y -qq "$pkg" || log_error "Failed: $pkg"
        fi
    done
}

install_go() {
    log_section "Go Language"
    if command -v go &>/dev/null; then
        log_info "Go already installed: $(go version)"
    else
        log_warn "Installing Go 1.22..."
        wget -q "https://go.dev/dl/go1.22.4.linux-amd64.tar.gz" -O /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        log_info "Go installed."
    fi
    export PATH="$PATH:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin:$HOME/go/bin"
    echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin:$HOME/go/bin' >> ~/.bashrc
}

install_go_tools() {
    log_section "Go Tools (${#GO_TOOLS[@]} tools)"
    export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:/usr/local/go/bin:$HOME/go/bin"

    for tool_path in "${GO_TOOLS[@]}"; do
        tool_name=$(basename "${tool_path%%@*}")
        if command -v "$tool_name" &>/dev/null; then
            log_info "$tool_name ✓"
        else
            log_warn "Installing $tool_name..."
            go install -v "$tool_path" 2>&1 | tail -1 || log_error "Failed: $tool_name"
        fi
    done
}

install_pip_tools() {
    log_section "Python/pip Tools"
    for tool in "${PIP_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null || pip3 show "$tool" &>/dev/null; then
            log_info "$tool ✓"
        else
            log_warn "Installing $tool..."
            pip3 install --user -q "$tool" 2>/dev/null || \
            pip3 install --break-system-packages -q "$tool" 2>/dev/null || \
            log_error "Failed: $tool"
        fi
    done
}

install_git_repos() {
    log_section "Git-Cloned Tools (${#GIT_REPOS[@]} repos)"
    mkdir -p "$TOOLS_DIR"

    for name in "${!GIT_REPOS[@]}"; do
        local repo_dir="$TOOLS_DIR/$name"
        if [[ -d "$repo_dir" ]]; then
            log_info "$name ✓"
        else
            log_warn "Cloning $name..."
            git clone --depth 1 -q "${GIT_REPOS[$name]}" "$repo_dir" 2>/dev/null || {
                log_error "Failed: $name"
                continue
            }
            # Install Python deps if present
            if [[ -f "$repo_dir/requirements.txt" ]]; then
                pip3 install --user -q -r "$repo_dir/requirements.txt" 2>/dev/null || true
            fi
            # Install setup.py if present
            if [[ -f "$repo_dir/setup.py" ]]; then
                (cd "$repo_dir" && pip3 install --user -q . 2>/dev/null) || true
            fi
        fi
    done
}

install_python_deps() {
    log_section "Python Project Dependencies"
    if [[ -f "requirements.txt" ]]; then
        pip3 install --user -q -r requirements.txt 2>/dev/null || \
        pip3 install --break-system-packages -q -r requirements.txt 2>/dev/null || \
        log_error "Failed to install requirements.txt"
    fi
}

install_findomain() {
    log_section "Findomain"
    if command -v findomain &>/dev/null; then
        log_info "findomain ✓"
    else
        log_warn "Installing findomain..."
        curl -sLo /tmp/findomain.zip "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" && \
        unzip -o -q /tmp/findomain.zip -d /tmp/ && \
        sudo mv /tmp/findomain /usr/local/bin/ && \
        sudo chmod +x /usr/local/bin/findomain && \
        rm /tmp/findomain.zip && \
        log_info "findomain installed." || log_error "Failed: findomain"
    fi
}

install_gf_patterns() {
    log_section "GF Patterns"
    if command -v gf &>/dev/null; then
        local gf_dir="$HOME/.gf"
        if [[ -d "$gf_dir" && "$(ls -A "$gf_dir" 2>/dev/null)" ]]; then
            log_info "GF patterns ✓"
        else
            mkdir -p "$gf_dir"
            git clone --depth 1 -q "https://github.com/1ndianl33t/Gf-Patterns.git" /tmp/gf-patterns 2>/dev/null && \
            cp /tmp/gf-patterns/*.json "$gf_dir/" && \
            rm -rf /tmp/gf-patterns && \
            log_info "GF patterns installed." || log_error "Failed: GF patterns"
        fi
    else
        log_warn "gf not installed — skipping pattern install."
    fi
}

update_nuclei_templates() {
    log_section "Nuclei Templates"
    if command -v nuclei &>/dev/null; then
        nuclei -update-templates 2>/dev/null || log_warn "Nuclei template update failed."
        log_info "Nuclei templates updated."
    fi
}

verify_installation() {
    log_section "Verification"
    local tools=(
        "subfinder" "amass" "assetfinder" "findomain"
        "httpx" "whatweb" "wafw00f"
        "naabu" "masscan" "nmap"
        "gowitness"
        "ffuf" "katana" "gospider"
        "gau" "waybackurls"
        "arjun" "paramspider"
        "gf"
        "crlfuzz" "sqlmap" "dalfox" "kxss" "commix"
        "nuclei" "nikto"
        "wpscan"
        "alterx" "puredns"
        "subzy" "subjack"
        "hakoriginfinder"
    )
    local installed=0
    local total=${#tools[@]}

    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_info "  ✓ $tool"
            installed=$((installed + 1))
        else
            log_error "  ✗ $tool"
        fi
    done

    echo ""
    log_info "Installed: $installed / $total core tools"

    if [[ $installed -lt $((total / 2)) ]]; then
        log_warn "Less than half of tools installed. Some modules will be skipped."
        log_warn "Use --check-tools to see which modules are affected."
    fi
}

main() {
    echo "══════════════════════════════════════════════════════════"
    echo "  BountyRecon v2.0 — Full Dependency Setup               "
    echo "  40+ tools across Recon, Exploitation, and Misc         "
    echo "══════════════════════════════════════════════════════════"
    echo ""

    check_root
    install_system_packages
    install_go
    install_go_tools
    install_findomain
    install_pip_tools
    install_git_repos
    install_gf_patterns
    install_python_deps
    update_nuclei_templates

    echo ""
    verify_installation
    echo ""
    log_info "Setup complete. Run: python3 bountyrecon.py -h"
    log_info "Tool directory: $TOOLS_DIR"
}

main "$@"
