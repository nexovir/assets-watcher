# Assets Watcher

This project automates DNS brute-forcing and subdomain discovery, integrating with tools like ShuffleDNS, DNSGen, and a database to store and track discovered assets.

## Features

- Automated DNS brute-force with **ShuffleDNS** and **DNSGen**.
- Subdomain discovery and integration with static and dynamically generated wordlists.
- Results are saved to a database and compared with existing records to avoid duplicates.
- Logging and messaging capabilities, including optional Telegram integration for notifications.
  
## Tools Used

- **ShuffleDNS**: For resolving subdomains.
- **DNSGen**: For generating permutations of subdomains.
- **SQLite**: Database used to store discovered subdomains.
- **Python**: Core programming language for automation and integration.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/nexovir/assets-watcher.git
