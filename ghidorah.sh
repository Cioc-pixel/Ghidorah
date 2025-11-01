#!/bin/zsh

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# Nuclei Templates path
TEMPLATE_PATH="My_templates"

# Configuration
TOR_CONTROL_PORT="127.0.0.1:9051"
TOR_PASSWORD="<PASSWORD_TOR>"
SOCKS_PROXY="socks5://127.0.0.1:9050"
THREADS=200
COMMON_PORTS="80,443,8080,8000,8888,8443,3000,5000,9000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

check_dependencies() {
    local deps=("urlfinder" "assetfinder" "subfinder" "httpx" "gau" "katana" "uro" "ffuf" "jq" "cowsay" "nuclei" "notify")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

change_tor_ip() {
    if echo -e 'AUTHENTICATE "PASSWORD_TOR"\nSIGNAL NEWNYM\nQUIT' | nc 127.0.0.1 9051 >/dev/null 2>&1; then
        print_success "Tor IP rotated"
        sleep 3
    else
        print_error "Failed to rotate Tor IP"
    fi
}

get_current_tor_ip() {
    torsocks curl -s https://check.torproject.org/api/ip | jq -r '.IP' 2>/dev/null || echo "Unknown"
}

subdomain_discovery() {
    local domain="$1"
    print_status "Starting subdomain discovery for: $domain"
    
    while IFS= read -r onedomain; do
        [[ -z "$onedomain" ]] && continue
        
        print_status "Processing domain: $onedomain"
        
        assetfinder "$onedomain" | tee -a assetfinder_domains.txt
        subfinder -d "$onedomain" -all -recursive | tee -a subfinder_domains.txt
        
    done < "$domain"
    
    # Combine and deduplicate
    cat assetfinder_domains.txt subfinder_domains.txt | sort -u > all_domains.txt
    local domain_count=$(wc -l < all_domains.txt)
    print_success "Found $domain_count unique subdomains"
    
    print_status "Probing alive domains with httpx..."
    httpx -l all_domains.txt -location -ip -status-code -content-length \
          -ports "$COMMON_PORTS" -threads "$THREADS" -silent | \
          tee alive_domains_full.txt
    
    # Extract clean URLs
    awk '{print $1}' alive_domains_full.txt | sort -u | shuf > urls.txt
    local alive_count=$(wc -l < urls.txt)
    print_success "Found $alive_count alive domains"
    
    echo -e "\nAlive domains found: $alive_count" | cowsay
}

crawling() {
    if [[ ! -f "urls.txt" ]]; then
        print_error "urls.txt not found. Run subdomain discovery first."
        return 1
    fi
    
    print_status "Starting crawling phase..."
    
    # Run gau and katana in parallel
    print_status "Running gau..."
    cat urls.txt | gau --subs --threads 20 2>/dev/null | tee gau_raw.txt &
    GAU_PID=$!
    
    print_status "Running katana..."
    katana -u urls.txt -d 2 -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg | tee katana_raw.txt &
    KATANA_PID=$!
    
    wait $GAU_PID $KATANA_PID
    
    # Process gau results
    print_status "Processing gau results..."
    cat gau_raw.txt | uro -o gau_processed.txt
    rm gau_raw.txt
    
    # Combine all URLs
    cat gau_processed.txt katana_raw.txt | sort -u > all_urls_combined.txt
    local total_urls=$(wc -l < all_urls_combined.txt)
    print_success "Found $total_urls total URLs"
    
    # Create organized output
    mkdir -p crawling_results
    
    # Categorize URLs
    print_status "Categorizing URLs..."
    
    grep '\?' all_urls_combined.txt > crawling_results/urls_with_params.txt
    grep '\.js$' all_urls_combined.txt > crawling_results/js_files.txt
    grep -E '\.(json|xml)$' all_urls_combined.txt > crawling_results/data_files.txt
    grep -Ei '(admin|login|auth|dashboard|panel)' all_urls_combined.txt > crawling_results/admin_urls.txt
    grep -Ei '(status|metrics|debug|config|info)' all_urls_combined.txt > crawling_results/status_urls.txt
    grep -Ei '(api|v[0-9])' all_urls_combined.txt > crawling_results/api_urls.txt
    
    # Count and display results
    print_success "Crawling results:"
    for file in crawling_results/*.txt; do
        local count=$(wc -l < "$file" 2>/dev/null || echo 0)
        echo "  $(basename "$file"): $count"
    done
}

pfuzzing() {
    if [[ ! -f "urls.txt" ]]; then
        print_error "urls.txt not found. Run subdomain discovery first."
        return 1
    fi
    
    print_status "Start passive fuzzing."
    
    urlfinder -list urls.txt -o passive_fuzzing_raw.txt
    cat passive_fuzzing_raw.txt | uro -o forscan.txt   
    print_status "Passive url fuzzing finished"
}

afuzzing() {
    if [[ ! -f "urls.txt" ]]; then
        print_error "urls.txt not found. Run subdomain discovery first."
        return 1
    fi
    
    print_status "Starting fuzzing phase with Tor rotation..."
    
    # Wordlist configuration
    local WORDLIST="${WORDLIST:-/home/busik/SecLists/Discovery/Web-Content/common.txt}"
    
    if [[ ! -f "$WORDLIST" ]]; then
        print_error "Wordlist not found: $WORDLIST"
        print_warning "Please set WORDLIST environment variable"
        return 1
    fi
    
    # Show current Tor IP
    print_status "Current Tor IP: $(get_current_tor_ip)"
    
    # Run ffuf with Tor rotation in background
    print_status "Starting ffuf directory fuzzing..."
    ffuf -u 'FUZZ1/FUZZ2' \
         -w 'urls.txt':FUZZ1 \
         -w "$WORDLIST":FUZZ2 \
         -rate 10 \
         -x "$SOCKS_PROXY" \
         -o fuzzing_results.json \
         -of json \
         -H 'User-Agent: Mozilla/6.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36' &
    
    FFUF_PID=$!
    
    # IP rotation loop
    local rotation_count=0
    while kill -0 $FFUF_PID 2>/dev/null; do
        kill -STOP $FFUF_PID
        change_tor_ip
        kill -CONT $FFUF_PID
        rotation_count=$((rotation_count + 1))
        print_status "Rotation #$rotation_count - New IP: $(get_current_tor_ip)"
        sleep 300
    done
    
    wait $FFUF_PID
    print_success "Fuzzing completed with $rotation_count IP rotations"
    
    # Convert JSON to readable format if results exist
    if [[ -f "fuzzing_results.json" ]] && [[ -s "fuzzing_results.json" ]]; then
        jq -r '.results[] | "\(.status): \(.url)"' fuzzing_results.json > fuzzing_results.txt
        local result_count=$(wc -l < fuzzing_results.txt)
        print_success "Found $result_count valid paths"
    fi
}

vuln() {
    if [[ ! -f "forscan.txt" ]]; then
        print_error "forscan.txt not found. Run urls fuzzing firstly discovery first."
        return 1
    fi
    
    print_status "Starting vulnerability scanning with Nuclei and Tor rotation..."
    
    # Show current Tor IP
    print_status "Current Tor IP: $(get_current_tor_ip)"
    
    # Run nuclei with Tor rotation in background
    nuclei -s critical,high -as -c 1 -rl 30 -bs 50 -rl 20 -l forscan.txt -proxy "$SOCKS_PROXY" | notify &
    
    NUCLEI_PID=$!
    
    # IP rotation loop
    local rotation_count=0
    while kill -0 $NUCLEI_PID 2>/dev/null; do
        kill -STOP $NUCLEI_PID
        change_tor_ip
        kill -CONT $NUCLEI_PID
        rotation_count=$((rotation_count + 1))
        print_status "Rotation #$rotation_count - New IP: $(get_current_tor_ip)"
        sleep 360
    done
    
    wait $NUCLEI_PID
    print_success "Vulnerability scanning completed with $rotation_count IP rotations"
}

generate_report() {
    print_status "Generating reconnaissance report..."
    
    local report="recon_report.txt"
    
    {
        echo "Reconnaissance Report - $(date)"
        echo "======================================"
        echo "Domain: $DOMAIN"
        echo ""
        
        echo "SUBDOMAIN DISCOVERY"
        echo "==================="
        if [[ -f "all_domains.txt" ]]; then
            echo "Total subdomains found: $(wc -l < all_domains.txt)"
        fi
        if [[ -f "urls.txt" ]]; then
            echo "Alive domains: $(wc -l < urls.txt)"
        fi
        echo ""
        
        echo "CRAWLING RESULTS"
        echo "================"
        if [[ -d "crawling_results" ]]; then
            for file in crawling_results/*.txt; do
                if [[ -f "$file" ]]; then
                    echo "$(basename "$file"): $(wc -l < "$file")"
                fi
            done
        fi
        echo ""
        
        echo "FUZZING RESULTS"
        echo "==============="
        if [[ -f "fuzzing_results.txt" ]]; then
            echo "Total paths found: $(wc -l < fuzzing_results.txt)"
            echo ""
            echo "Top status codes:"
            awk '{print $1}' fuzzing_results.txt | sort | uniq -c | sort -nr
        fi
        echo ""
        
        echo "TOR USAGE"
        echo "=========="
        echo "IP rotations during scanning: $rotation_count"
        
    } > "$report"
    
    print_success "Report generated: $report"
}

cleanup() {
    print_status "Cleaning up temporary files..."
    rm -f assetfinder_domains.txt subfinder_domains.txt gau_raw.txt katana_raw.txt
    print_success "Cleanup completed"
}

main() {
    # Display ASCII art
    if [[ -f ~/.ascii_art/ascii ]]; then
        cat ~/.ascii_art/ascii
    fi
    
    # Validate input
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <domain> [subs|crawl|fuzz|vuln|all]"
        echo ""
        echo "Options:"
        echo "  subs    - Subdomain discovery only"
        echo "  crawl   - Crawling only (requires subs first)"
        echo "  pfuzz    - Passive Fuzzing urlfinder"
        echo "  afuzz    - Fuzzing with Tor rotation only"
        echo "  vuln    - Vulnerability scanning with Tor rotation only"
        echo "  all     - Run complete reconnaissance"
        echo ""
        echo "Examples:"
        echo "  $0 example.com all"
        echo "  $0 example.com subs crawl"
        echo "  $0 example.com fuzz"
        exit 1
    fi
    
    DOMAIN="$1"
    shift
    ARGS=("$@")
    
    # Check dependencies
    check_dependencies
    
    print_success "Target domain: $DOMAIN"
    
    # If no specific arguments, run everything
    if [[ ${#ARGS[@]} -eq 0 ]]; then
        ARGS=("all")
    fi
    
    # Process arguments
    for arg in "${ARGS[@]}"; do
        case "$arg" in
            "subs")
                subdomain_discovery "$DOMAIN"
                ;;
            "crawl")
                crawling
                ;;
            "afuzz")
                afuzzing
                ;;
            "pfuzz")
            	pfuzzing
		;;
            "vuln")
                vuln
                ;;
            "all")
                print_status "Running complete reconnaissance pipeline..."
                subdomain_discovery "$DOMAIN"
                crawling
                fuzzing
                vuln
                ;;
            *)
                print_warning "Unknown argument: $arg"
                echo "Valid arguments: subs, crawl, fuzz, vuln, all"
                ;;
        esac
    done
    
    # Generate final report
    generate_report
    
    # Cleanup
    cleanup
    
    print_success "Reconnaissance completed successfully!"
}

# Trap Ctrl+C for graceful exit
trap 'print_error "Script interrupted"; cleanup; exit 1' INT

# Run main function with all arguments
main "$@"
