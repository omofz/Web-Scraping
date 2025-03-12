import re
import json
import pandas as pd
from datetime import datetime
import argparse
import os


class LogParser:
    def __init__(self):
        # Common log format patterns
        self.patterns = {
            'apache': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d+) (\d+|-)',
            'nginx': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - .* \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
            'app': r'\[(.*?)\] \[(\w+)\] \[(.*?)\] (.*)'
        }
        
    def detect_format(self, log_sample):
        """Auto-detect log format based on a sample line"""
        for format_name, pattern in self.patterns.items():
            if re.match(pattern, log_sample):
                return format_name
        return None
    
    def parse_request(self, request_string):
        """Parse the request string into method, path, and HTTP version"""
        parts = request_string.split()
        if len(parts) >= 2:
            method = parts[0]
            path = parts[1]
            http_version = parts[2] if len(parts) > 2 else ""
            return method, path, http_version
        return "", "", ""
    
    def parse_apache(self, line):
        """Parse Apache/Common Log Format lines"""
        pattern = self.patterns['apache']
        match = re.match(pattern, line)
        if match:
            ip, timestamp, request, status, bytes_sent = match.groups()
            method, path, http_version = self.parse_request(request)
            
            # Convert timestamp to datetime
            try:
                timestamp = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                # Handle timestamp parsing errors
                pass
                
            # Handle case where bytes_sent is '-'
            if bytes_sent == '-':
                bytes_sent = 0
                
            return {
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "path": path,
                "http_version": http_version,
                "status": int(status),
                "bytes_sent": int(bytes_sent),
                "raw_entry": line
            }
        return None
    
    def parse_nginx(self, line):
        """Parse Nginx log format lines"""
        pattern = self.patterns['nginx']
        match = re.match(pattern, line)
        if match:
            ip, timestamp, request, status, bytes_sent, referrer, user_agent = match.groups()
            method, path, http_version = self.parse_request(request)
            
            try:
                timestamp = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                pass
                
            return {
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "path": path,
                "http_version": http_version,
                "status": int(status),
                "bytes_sent": int(bytes_sent),
                "referrer": referrer,
                "user_agent": user_agent,
                "raw_entry": line
            }
        return None
    
    def parse_app_log(self, line):
        """Parse application log format lines"""
        pattern = self.patterns['app']
        match = re.match(pattern, line)
        if match:
            timestamp, level, module, message = match.groups()
            
            try:
                timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S,%f")
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass
                    
            return {
                "timestamp": timestamp,
                "level": level,
                "module": module,
                "message": message,
                "raw_entry": line
            }
        return None
    
    def parse_log(self, file_path, log_format=None, max_lines=None):
        """Parse log file and return structured data"""
        parsed_entries = []
        line_count = 0
        
        # Detect the log format if not specified
        if not log_format:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                first_line = file.readline().strip()
                log_format = self.detect_format(first_line)
                if not log_format:
                    raise ValueError("Could not detect log format. Please specify explicitly.")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                    
                entry = None
                if log_format == 'apache':
                    entry = self.parse_apache(line)
                elif log_format == 'nginx':
                    entry = self.parse_nginx(line)
                elif log_format == 'app':
                    entry = self.parse_app_log(line)
                
                if entry:
                    parsed_entries.append(entry)
                
                line_count += 1
                if max_lines and line_count >= max_lines:
                    break
                    
        return parsed_entries
    
    def to_dataframe(self, parsed_entries):
        """Convert parsed entries to a Pandas DataFrame"""
        if not parsed_entries:
            return pd.DataFrame()
        return pd.DataFrame(parsed_entries)
    
    def to_json(self, parsed_entries, output_file=None):
        """Convert parsed entries to JSON format"""
        # Handle datetime serialization
        def datetime_handler(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        json_data = json.dumps(parsed_entries, default=datetime_handler, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_data)
        
        return json_data
    
    def analyze(self, parsed_entries):
        """Perform basic analysis on parsed log entries"""
        if not parsed_entries:
            return {"error": "No entries to analyze"}
            
        analysis = {}
        
        # Check if entries have IP addresses (web server logs)
        if "ip" in parsed_entries[0]:
            # Count requests by IP
            ip_counts = {}
            for entry in parsed_entries:
                ip = entry["ip"]
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            analysis["top_ips"] = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Count status codes
            status_counts = {}
            for entry in parsed_entries:
                status = entry["status"]
                status_counts[status] = status_counts.get(status, 0) + 1
            analysis["status_codes"] = status_counts
            
            # Most requested paths
            if "path" in parsed_entries[0]:
                path_counts = {}
                for entry in parsed_entries:
                    path = entry["path"]
                    path_counts[path] = path_counts.get(path, 0) + 1
                analysis["top_paths"] = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Check if entries have log levels (application logs)
        if "level" in parsed_entries[0]:
            # Count log levels
            level_counts = {}
            for entry in parsed_entries:
                level = entry["level"]
                level_counts[level] = level_counts.get(level, 0) + 1
            analysis["log_levels"] = level_counts
            
            # Count by module
            if "module" in parsed_entries[0]:
                module_counts = {}
                for entry in parsed_entries:
                    module = entry["module"]
                    module_counts[module] = module_counts.get(module, 0) + 1
                analysis["top_modules"] = sorted(module_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return analysis

def main():
    parser = argparse.ArgumentParser(description="Parse and analyze log files")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument("--format", choices=["apache", "nginx", "app"], 
                        help="Log format (auto-detect if not specified)")
    parser.add_argument("--output", help="Output file path for JSON results")
    parser.add_argument("--max-lines", type=int, help="Maximum number of lines to parse")
    parser.add_argument("--analyze", action="store_true", help="Perform basic analysis on logs")
    parser.add_argument("--csv", help="Save results as CSV file")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: Log file '{args.log_file}' not found")
        return
    
    log_parser = LogParser()
    
    try:
        # Parse the log file
        parsed_entries = log_parser.parse_log(
            args.log_file, 
            log_format=args.format, 
            max_lines=args.max_lines
        )
        
        print(f"Successfully parsed {len(parsed_entries)} log entries")
        
        # Save as JSON if output file specified
        if args.output:
            log_parser.to_json(parsed_entries, args.output)
            print(f"Results saved to {args.output}")
        
        # Save as CSV if specified
        if args.csv:
            df = log_parser.to_dataframe(parsed_entries)
            df.to_csv(args.csv, index=False)
            print(f"Results saved to {args.csv}")
        
        # Perform analysis if requested
        if args.analyze:
            analysis = log_parser.analyze(parsed_entries)
            print("\nLog Analysis:")
            print(json.dumps(analysis, indent=2))
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()