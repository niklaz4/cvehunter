#!/usr/bin/env python3
import requests
import argparse
from datetime import datetime, timedelta
import json
import sys
import os
import csv
import sqlite3
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from pathlib import Path

class AttackHunter:
    def __init__(self):
        # Atualizado para usar a versão atual da API do MITRE ATT&CK
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.enterprise_url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
        self.console = Console()
        self.cache_dir = Path.home() / '.attackhunter'
        self.cache_db = self.cache_dir / 'cache.db'
        self.initialize_cache()
        
    def show_banner(self):
        banner = """
   ______     _______ __  __             __           
  / ____/  __/ ____/ / / / /_  ______  / /____  _____
 / /   | |/_/ __/ / /_/ / / / / / __ \/ __/ _ \/ ___/
 / /___>  </ /___/ __  / / /_/ / / / / /_/  __/ /    
 \____/_/|_/_____/_/ /_/_/\__,_/_/ /_/\__/\___/_/     
                                                      
        [ CVE Hunter - Threat Tactics & Techniques ]
        [ Version 1.0 - MITRE ATT&CK Integration ]
	    [ Author: N. "M1racle" A. ]
        """
        self.console.print(Panel(banner, style="bold blue"))
    
    def initialize_cache(self):
        self.cache_dir.mkdir(exist_ok=True)
        conn = sqlite3.connect(str(self.cache_db))
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS attack_cache
                    (query TEXT PRIMARY KEY, data TEXT, timestamp TEXT)''')
        conn.commit()
        conn.close()

    def get_from_cache(self, query_key):
        conn = sqlite3.connect(str(self.cache_db))
        c = conn.cursor()
        c.execute("SELECT data, timestamp FROM attack_cache WHERE query = ?", (query_key,))
        result = c.fetchone()
        conn.close()
        
        if result:
            data, timestamp = result
            cache_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            if datetime.now() - cache_time < timedelta(hours=24):
                return json.loads(data)
        return None

    def save_to_cache(self, query_key, data):
        conn = sqlite3.connect(str(self.cache_db))
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO attack_cache VALUES (?, ?, ?)",
                 (query_key, json.dumps(data), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()

    def fetch_attack_data(self):
        """Fetch the complete MITRE ATT&CK Enterprise dataset"""
        try:
            response = requests.get(self.enterprise_url, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                self.console.print(f"[red]Error fetching ATT&CK data: {response.status_code}[/red]")
                return None
        except Exception as e:
            self.console.print(f"[red]Error: {str(e)}[/red]")
            return None

    def get_techniques(self, attack_data, tactic_id=None):
        """Extract techniques from the ATT&CK dataset"""
        if not attack_data:
            return []

        techniques = []
        tactic_name = None

        # If tactic_id is provided, first find the tactic name
        if tactic_id:
            for obj in attack_data['objects']:
                if obj.get('type') == 'x-mitre-tactic' and obj.get('external_references'):
                    for ref in obj['external_references']:
                        if ref.get('external_id') == tactic_id:
                            tactic_name = obj.get('name')
                            break
                    if tactic_name:
                        break

        # Extract techniques
        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                # If tactic_id is provided, only include techniques for that tactic
                if tactic_id:
                    if obj.get('kill_chain_phases'):
                        for phase in obj['kill_chain_phases']:
                            if phase.get('phase_name') == tactic_name:
                                techniques.append(obj)
                                break
                else:
                    techniques.append(obj)

        return techniques

    def get_severity_level(self, technique):
        """Determine severity based on technique characteristics"""
        score = 0
        
        # Check for sub-techniques
        if technique.get('x_mitre_deprecated', False):
            score += 1
            
        # Check platforms affected
        platforms = technique.get('x_mitre_platforms', [])
        if len(platforms) > 3:
            score += 2
            
        # Check for defense bypassed
        if technique.get('x_mitre_defense_bypassed', []):
            score += 2
            
        # Check permissions required
        if not technique.get('x_mitre_permissions_required', []):
            score += 1
            
        # Evaluate based on score
        if score >= 4:
            return "CRÍTICO"
        elif score >= 3:
            return "ALTO"
        elif score >= 2:
            return "MÉDIO"
        return "BAIXO"

    def prepare_technique_data(self, technique):
        """Prepare technique data for display"""
        technique_id = "N/A"
        for ref in technique.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                technique_id = ref.get('external_id')
                break
                
        return {
            'Technique_ID': technique_id,
            'Name': technique.get('name', 'N/A'),
            'Tactic': ', '.join([phase['phase_name'] for phase in technique.get('kill_chain_phases', [])]),
            'Severity': self.get_severity_level(technique),
            'Platforms': ', '.join(technique.get('x_mitre_platforms', [])),
            'Detection': technique.get('x_mitre_detection', 'N/A'),
            'Description': technique.get('description', 'No description available')
        }

    def search_techniques(self, keyword=None, tactic=None, max_results=50, min_severity=None, 
                         export_format=None, export_file=None):
        cache_key = f"{keyword}_{tactic}_{max_results}_{min_severity}"
        techniques = self.get_from_cache(cache_key)
        
        if not techniques:
            attack_data = self.fetch_attack_data()
            if not attack_data:
                return
                
            techniques = self.get_techniques(attack_data, tactic)
            
            if keyword:
                techniques = [
                    tech for tech in techniques 
                    if keyword.lower() in tech.get('name', '').lower() or 
                       keyword.lower() in tech.get('description', '').lower()
                ]
            
            self.save_to_cache(cache_key, techniques)
        
        if min_severity:
            techniques = [
                tech for tech in techniques 
                if self.get_severity_level(tech) == min_severity
            ]
        
        techniques = techniques[:max_results]
        
        if export_format:
            if export_format.lower() == 'csv':
                self.export_to_csv(techniques, export_file or 'techniques.csv')
            elif export_format.lower() == 'json':
                self.export_to_json(techniques, export_file or 'techniques.json')
            else:
                self.console.print("[red]Unsupported export format.[/red]")
        else:
            self.display_results(techniques)

    def export_to_csv(self, techniques, filename):
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Technique_ID', 'Name', 'Tactic', 'Severity', 
                         'Platforms', 'Detection', 'Description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for tech in techniques:
                row = self.prepare_technique_data(tech)
                writer.writerow(row)
        
        self.console.print(f"[green]Data exported to {filename}[/green]")

    def export_to_json(self, techniques, filename):
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(techniques, jsonfile, indent=2, ensure_ascii=False)
        self.console.print(f"[green]Data exported to {filename}[/green]")

    def display_results(self, techniques):
        if not techniques:
            self.console.print("[yellow]No techniques found matching the criteria.[/yellow]")
            return

        table = Table(title="ATT&CK Techniques Found")
        table.add_column("Technique ID", justify="left", style="cyan")
        table.add_column("Name", justify="left", style="green")
        table.add_column("Tactic", justify="center")
        table.add_column("Severity", justify="center")
        table.add_column("Platforms", justify="left")
        table.add_column("Description", justify="left", max_width=50)

        for tech in techniques:
            row = self.prepare_technique_data(tech)
            severity_style = {
                "CRÍTICO": "red bold",
                "ALTO": "red",
                "MÉDIO": "yellow",
                "BAIXO": "green"
            }.get(row['Severity'], "white")
            
            table.add_row(
                row['Technique_ID'],
                row['Name'],
                row['Tactic'],
                f"[{severity_style}]{row['Severity']}[/]",
                row['Platforms'],
                row['Description'][:100] + "..." if len(row['Description']) > 100 else row['Description']
            )

        self.console.print(table)

def main():
    parser = argparse.ArgumentParser(description="ATT&CK Hunter - Search MITRE ATT&CK Techniques")
    parser.add_argument('-k', '--keyword', type=str, help='Keyword to search in techniques')
    parser.add_argument('-t', '--tactic', type=str, help='Tactic ID (e.g., TA0001)')
    parser.add_argument('-m', '--max-results', type=int, default=50, help='Maximum number of results')
    parser.add_argument('-s', '--min-severity', type=str, choices=['CRÍTICO', 'ALTO', 'MÉDIO', 'BAIXO'],
                        help='Minimum severity level')
    parser.add_argument('-e', '--export-format', type=str, choices=['csv', 'json'], help='Export format')
    parser.add_argument('-f', '--export-file', type=str, help='Export file name')

    args = parser.parse_args()

    hunter = AttackHunter()
    hunter.show_banner()
    hunter.search_techniques(
        keyword=args.keyword,
        tactic=args.tactic,
        max_results=args.max_results,
        min_severity=args.min_severity,
        export_format=args.export_format,
        export_file=args.export_file
    )

if __name__ == "__main__":
    main()
