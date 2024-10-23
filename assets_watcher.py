import os
import re
from bs4 import BeautifulSoup
import colorama
import argparse
import subprocess
import pydig
import sqlite3
import time 
import schedule

# Initialize colorama for terminal colors
color = colorama.Fore
color_reset = colorama.Style.RESET_ALL

# Function for sending messages with optional Telegram integration and logging
def sendmessage(message: str, telegram: bool = False, colour: str = "YELLOW", logger: bool = True):
    color = getattr(colorama.Fore, colour, colorama.Fore.YELLOW)
    print(color + message + colorama.Style.RESET_ALL)
    
    # Get the current time and format it
    time_string = time.strftime("%d/%m/%Y, %H:%M:%S", time.localtime())
    
    # Log the message if logger is True
    if logger:
        with open('logger.txt', 'a') as file:
            file.write(message + ' -> ' + time_string + '\n')

    # Send message via Telegram if enabled
    if telegram:
        message = message.replace(' ', '+')
        command = f'curl -X POST "https://api.telegram.org/bot<your_bot_token>/sendMessage" -d "chat_id=<your_chat_id>&text={message}"'
        subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

# Function to clean specified file
def file_cleaner(filename: str):
    clean_file = input(f"{colorama.Fore.YELLOW}Do you want to clean {colorama.Fore.RED}{filename}{colorama.Fore.YELLOW}? (yes/no): ").strip().lower()

    if clean_file in ['yes', 'y']:
        with open(filename, 'w') as f:
            f.truncate(0)
        sendmessage(f"File {filename} has been cleaned.", telegram=False, logger=True)
    elif clean_file in ['no', 'n']:
        sendmessage(f"No changes made at {filename}", telegram=False, logger=True)
    else:
        sendmessage("Invalid input. No changes made.", telegram=False, logger=True, colour="RED")

# Argument parser for command line inputs
parser = argparse.ArgumentParser(description='A powerful watcher for finding new subdomains')
parser.add_argument('-d', '--domain', help='Domain for watching', metavar="", default=None, required=True)
parser.add_argument('-re', '--remove', help='Delete some domain of watching', metavar="", default=0, required=False)
parser.add_argument('-st', '--subfindertime', help='Time interval for subfinder (hours)', metavar="", default=0, required=False)
parser.add_argument('-dt', '--dnsbrutetime', help='Time interval for DNS bruteforce (hours)', metavar="", default=0, required=False)

args = parser.parse_args()
domain = args.domain.split(',')
subfinder_time = args.subfindertime
dnsbrute_time = args.dnsbrutetime
column_delete = args.remove

# Database connection
conn = sqlite3.connect('../../program_assets.db')
cursor = conn.cursor()

# Function to delete a column from the ASSETS table
def delete_column(column_delete: str):
    column_delete = column_delete.replace('.', '_').replace('-', '_')
    
    # Fetch all columns in the ASSETS table
    cursor.execute("PRAGMA table_info(ASSETS)")
    columns = cursor.fetchall()
    
    # Check if the column exists
    if column_delete not in [col[1] for col in columns]:
        sendmessage(f"{color.RED}The column '{column_delete}' does not exist in the ASSETS table.{color_reset}", colour="RED")
        return
    
    # Recreate the table without the specified column
    new_columns = [col[1] for col in columns if col[1] != column_delete]
    columns_str = ', '.join(new_columns)
    
    cursor.execute(f"CREATE TABLE ASSETS_temp AS SELECT {columns_str} FROM ASSETS")
    cursor.execute("DROP TABLE ASSETS")
    cursor.execute(f"ALTER TABLE ASSETS_temp RENAME TO ASSETS")
    conn.commit()

    sendmessage(f"The column '{column_delete}' was successfully removed.", telegram=True)

# Function to create the ASSETS table and add columns for each domain
def creating_tables(database: str, table: str, domain: list):
    cursor.execute(f"CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY AUTOINCREMENT)")
    cursor.execute(f"PRAGMA table_info({table})")
    existing_columns = [info[1] for info in cursor.fetchall()]

    for single_domain in domain:
        column_name = single_domain.replace('.', '_').replace('-', '_')
        
        if column_name not in existing_columns:
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} TEXT")
            except sqlite3.OperationalError as e:
                sendmessage(f"Error at {column_name}: {e}", colour="RED")
    
    conn.commit()

# Function to compare two lists and return unique elements from list1
def compare_lists(list1, list2):
    return [sub1 for sub1 in list1 if sub1 not in list2]

# Subfinder function to find new subdomains
def subfinder():
    for single_domain in domain:
        cursor.execute(f"SELECT {single_domain.replace('.', '_').replace('-', '_')} FROM ASSETS")
        old_subs = [row[0] for row in cursor.fetchall() if row[0] is not None]

        sendmessage(f"Starting Subfinder for '{single_domain}'... Please Wait", telegram=True, logger=True)
        subs = os.popen(f"subfinder -d {single_domain} -silent -timeout 20 -max-time 20").read().split('\n')
        sendmessage(f"[+] Found {str(len(subs))} subdomains from Subfinder", colour='GREEN')

        new_subs_filtered = [sub for sub in subs if sub not in old_subs]

        cursor.execute(f"SELECT rowid FROM ASSETS")
        row_ids = [row[0] for row in cursor.fetchall()]

        if len(new_subs_filtered) > len(row_ids):
            additional_rows = len(new_subs_filtered) - len(row_ids)
            for _ in range(additional_rows):
                cursor.execute(f"INSERT INTO ASSETS ({single_domain.replace('.', '_').replace('-', '_')}) VALUES (NULL)")

        for row_id, new_value in zip(row_ids, new_subs_filtered):
            cursor.execute(f"UPDATE ASSETS SET {single_domain.replace('.', '_').replace('-', '_')} = ? WHERE rowid = ?", (new_value, row_id))

        conn.commit()

        subfinder_discovered = compare_lists(subs, old_subs)
        if subfinder_discovered:
            time_string = time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime())
            sendmessage(f"Found New Subdomain(s): {str(subfinder_discovered)} -> {time_string}", colour="GREEN")
            with open('subs.discovered', 'a') as file:
                for sub in subfinder_discovered:
                    file.write(f"{sub} -> {time_string}\n")

    time_string = time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime())
    sendmessage(f"Subfinder completed at -> {time_string}", telegram=True, logger=True)

# DNS brute force function
def dnsbrute():
    def check_a_record(domain: str) -> bool:
        sendmessage(f"Checking for A record...", colour="YELLOW")
        full_domain = f"somedomaindosentexist.{domain}"
        try:
            result = pydig.query(full_domain, 'A')
            if result:
                sendmessage("Verification failed.", colour="RED")
                return False
            else:
                sendmessage("Verification successful.", colour="GREEN")
                return True
        except KeyError as e:
            sendmessage(f"Error: {e}", colour="RED")

    # Get subdomains from database and wordlist
    def get_subdomains(domain: str):
        subdomains = []

        cursor.execute(f"SELECT {domain.replace('.', '_').replace('-', '_')} FROM ASSETS")
        old_subs = [row[0] for row in cursor.fetchall() if row[0] is not None]
        subdomains.extend([sub.replace(f'.{domain}', '') for sub in old_subs])

        with open('outputs/2m-subdomains.subs', 'r') as file:
            subdomains.extend([line.strip() for line in file])

        sendmessage(f"Found {len(set(subdomains))} subdomains.", colour="GREEN")
        return set(subdomains)

    def create_dnsgen_subs(shuffledns: list, domain: str):
        sub_subdomains = [line.strip() for line in open('outputs/sub-subdomains.txt', 'r')]
        dns_gen_subs = set(shuffledns + sub_subdomains)
        with open('outputs/dns_gen.subs', 'w') as file:
            file.writelines(f"{sub}\n" for sub in dns_gen_subs)

    def add_to_file(dns_bruteforce_discovered: list):
        filename = 'subs/subfinder.subs'
        try:
            existing_lines = {line.strip() for line in open(filename, 'r', encoding='utf-8')}
            with open(filename, 'a', encoding='utf-8') as file:
                for item in dns_bruteforce_discovered:
                    if item not in existing_lines:
                        file.write(f"{item}\n")
        except FileNotFoundError:
            sendmessage(f"File {filename} not found.")
        except Exception as e:
            sendmessage(f"An error occurred: {e}")
    for single_domain in domain:
        if check_a_record(single_domain):
            sendmessage(f"Starting DNSBruteforce at {single_domain}", telegram=True)
            
            # Get subdomains for ShuffleDNS input
            subdomains = get_subdomains(single_domain)
            
            sendmessage(f'{color.WHITE}Starting Shuffledns on {color.YELLOW}Discovered Subs & Static Wordlist...{color_reset}')
            resolve1 = os.popen(f"shuffledns -d {single_domain} -w outputs/all-subdomains.txt -r outputs/resolvers.txt -o outputs/shuffle_out.txt -silent").read().split('\n')
            
            sendmessage(f'{color.WHITE}Starting {color.YELLOW}DnsGen...{color_reset}')
            create_dnsgen_subs(resolve1, single_domain)
            
            os.popen("dnsgen outputs/dns_gen.subs | tee outputs/dns_gen_out.subs").read()
            
            sendmessage(f'{color.WHITE}Starting Shuffledns on {color.YELLOW}DnsGen...{color_reset}')
            resolve2 = os.popen(f"shuffledns -d {single_domain} -w outputs/dns_gen_out.subs -r outputs/resolvers.txt -o outputs/dns_gen_shuffle_out.txt -silent").read()
            
            sendmessage(f'{color.WHITE}Saving...{color_reset}')
            
            final = []
            with open('outputs/shuffle_out.txt', 'r') as file:
                final.extend([line.strip() for line in file])
                
            with open('outputs/dns_gen_shuffle_out.txt', 'r') as file:
                final.extend([line.strip() for line in file])
            
            final = set(final)  # Remove duplicates
            
            # Fetch existing subdomains from the database
            cursor.execute(f"SELECT {single_domain.replace('.', '_').replace('-', '_')} FROM ASSETS")
            existing_values = {row[0] for row in cursor.fetchall()}
            
            for item in final:
                if item not in existing_values:
                    cursor.execute(f"INSERT INTO ASSETS ({single_domain.replace('.', '_').replace('-', '_')}) VALUES (?)", (item,))
                    sendmessage(f"[+] '{item}' -> [DNSBruteforce discovered]", telegram=False, colour="GREEN")
                else:
                    sendmessage(f"[-] '{item}' -> [exists in database]", telegram=False, colour="RED")
            
            conn.commit()
        else:
            pass
    
    # Log DNSBrute completion time
    time_string = time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime())
    sendmessage(f'DnsBrute was successfully done at -> {time_string}', telegram=True, logger=True)

# Clean logger file
file_cleaner('logger.txt')

# Initial startup message
sendmessage(f"You start watching for {args.domain}, subfinder_time: {args.subfindertime} hours, dnsbrute_time: {args.dnsbrutetime} hours, remove: \"{column_delete}\" from columns", colour="CYAN", telegram=False)

# Delete column if requested
if column_delete != 0:
    delete_column(column_delete)

# Create database table and run initial subfinder scan
creating_tables('../../program_assets.db', 'ASSETS', domain)
subfinder()

# Schedule recurring tasks for subfinder and DNSBruteforce
schedule.every(int(subfinder_time)).hours.do(subfinder)
schedule.every(int(dnsbrute_time)).hours.do(dnsbrute)

# Continuously run scheduled tasks
while True:
    schedule.run_pending()
    time.sleep(1)
