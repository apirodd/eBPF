#!/usr/bin/env python3
"""
HTTP Client Metrics Collector for DDoS Resilience Testing
Measures service availability and performance during attack conditions
"""

import requests
import time
import statistics
import csv
import sys
from datetime import datetime
from urllib.parse import urlparse

class HTTPMetricsCollector:
    def __init__(self, target_url, interval=1.0, timeout=5.0):
        self.target_url = target_url
        self.interval = interval
        self.timeout = timeout
        self.metrics = {
            'timestamps': [],
            'response_times': [],
            'status_codes': [],
            'successful_requests': 0,
            'failed_requests': 0,
            'timeout_requests': 0,
            'ttfb_values': []  # Time To First Byte
        }
        
        # CSV logging setup
        self.csv_file = f"http_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.setup_csv_log()
        
    def setup_csv_log(self):
        """Initialize CSV file with headers"""
        with open(self.csv_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'timestamp', 'response_time_ms', 'status_code', 
                'success', 'ttfb_ms', 'bytes_received'
            ])
    
    def log_to_csv(self, timestamp, response_time, status_code, success, ttfb, bytes_len):
        """Log individual request metrics to CSV"""
        with open(self.csv_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                timestamp, response_time, status_code, 
                success, ttfb, bytes_len
            ])
    
    def make_request(self):
        """Make HTTP request and collect timing metrics"""
        start_time = time.time()
        success = False
        status_code = 0
        response_time = 0
        ttfb = 0
        bytes_received = 0
        
        try:
            # Measure TTFB and total response time
            with requests.get(self.target_url, timeout=self.timeout, stream=True) as response:
                # Time to first byte
                ttfb = (time.time() - start_time) * 1000
                
                # Read full response to get complete timing
                content = response.content
                response_time = (time.time() - start_time) * 1000
                
                status_code = response.status_code
                bytes_received = len(content)
                success = (200 <= status_code < 400)
                
        except requests.exceptions.Timeout:
            response_time = self.timeout * 1000
            success = False
            status_code = 0
            
        except requests.exceptions.ConnectionError:
            response_time = (time.time() - start_time) * 1000
            success = False
            status_code = 0
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            success = False
            status_code = 0
        
        return {
            'success': success,
            'response_time': response_time,
            'status_code': status_code,
            'ttfb': ttfb,
            'bytes_received': bytes_received,
            'timestamp': datetime.now().isoformat()
        }
    
    def collect_metrics(self, duration_seconds=None, max_requests=None):
        """Main metrics collection loop"""
        request_count = 0
        start_time = time.time()
        
        print(f"Starting HTTP metrics collection for {self.target_url}")
        print("Press Ctrl+C to stop early\n")
        
        try:
            while True:
                # Check duration limit
                if duration_seconds and (time.time() - start_time) > duration_seconds:
                    break
                
                # Check request count limit
                if max_requests and request_count >= max_requests:
                    break
                
                # Make request and collect metrics
                result = self.make_request()
                
                # Store metrics
                self.metrics['timestamps'].append(result['timestamp'])
                self.metrics['response_times'].append(result['response_time'])
                self.metrics['status_codes'].append(result['status_code'])
                self.metrics['ttfb_values'].append(result['ttfb'])
                
                if result['success']:
                    self.metrics['successful_requests'] += 1
                else:
                    self.metrics['failed_requests'] += 1
                    if result['response_time'] >= self.timeout * 1000:
                        self.metrics['timeout_requests'] += 1
                
                # Log to CSV
                self.log_to_csv(
                    result['timestamp'],
                    result['response_time'],
                    result['status_code'],
                    int(result['success']),
                    result['ttfb'],
                    result['bytes_received']
                )
                
                # Display progress
                request_count += 1
                if request_count % 10 == 0:
                    self.display_progress()
                
                # Wait for next interval
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            print("\nCollection stopped by user")
        
        finally:
            self.generate_summary_report()
    
    def display_progress(self):
        """Display current progress metrics"""
        total = self.metrics['successful_requests'] + self.metrics['failed_requests']
        if total == 0:
            return
            
        success_rate = (self.metrics['successful_requests'] / total) * 100
        avg_response = statistics.mean(self.metrics['response_times']) if self.metrics['response_times'] else 0
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
              f"Requests: {total} | "
              f"Success: {success_rate:.1f}% | "
              f"Avg RT: {avg_response:.1f}ms")
    
    def generate_summary_report(self):
        """Generate comprehensive summary report"""
        total_requests = len(self.metrics['response_times'])
        if total_requests == 0:
            print("No requests were made")
            return
        
        success_rate = (self.metrics['successful_requests'] / total_requests) * 100
        timeout_rate = (self.metrics['timeout_requests'] / total_requests) * 100
        
        # Calculate statistics
        response_times = self.metrics['response_times']
        ttfb_times = [t for t in self.metrics['ttfb_values'] if t > 0]
        
        avg_response = statistics.mean(response_times) if response_times else 0
        avg_ttfb = statistics.mean(ttfb_times) if ttfb_times else 0
        
        p95_response = statistics.quantiles(response_times, n=20)[-1] if len(response_times) > 1 else 0
        p95_ttfb = statistics.quantiles(ttfb_times, n=20)[-1] if len(ttfb_times) > 1 else 0
        
        print("\n" + "="*60)
        print("HTTP METRICS COLLECTION SUMMARY")
        print("="*60)
        print(f"Target URL: {self.target_url}")
        print(f"Time period: {self.metrics['timestamps'][0]} to {self.metrics['timestamps'][-1]}")
        print(f"Total requests: {total_requests}")
        print(f"Successful requests: {self.metrics['successful_requests']}")
        print(f"Failed requests: {self.metrics['failed_requests']}")
        print(f"Timeout requests: {self.metrics['timeout_requests']}")
        print(f"Success rate: {success_rate:.2f}%")
        print(f"Timeout rate: {timeout_rate:.2f}%")
        print(f"Average response time: {avg_response:.2f} ms")
        print(f"95th percentile response time: {p95_response:.2f} ms")
        print(f"Average TTFB: {avg_ttfb:.2f} ms")
        print(f"95th percentile TTFB: {p95_ttfb:.2f} ms")
        print("="*60)
        print(f"Detailed metrics saved to: {self.csv_file}")
        
        # Generate a simple plot if matplotlib is available
        try:
            import matplotlib.pyplot as plt
            self.generate_plots()
        except ImportError:
            print("Matplotlib not available - skipping plots")
    
    def generate_plots(self):
        """Generate visualization plots"""
        # Response time over time
        plt.figure(figsize=(12, 8))
        
        # Plot 1: Response times
        plt.subplot(2, 2, 1)
        plt.plot(self.metrics['response_times'])
        plt.title('Response Time Over Time')
        plt.xlabel('Request Number')
        plt.ylabel('Response Time (ms)')
        plt.grid(True)
        
        # Plot 2: Success rate rolling window
        plt.subplot(2, 2, 2)
        window_size = min(50, len(self.metrics['response_times']) // 10)
        success_rolling = []
        for i in range(len(self.metrics['response_times'])):
            start = max(0, i - window_size)
            window = self.metrics['response_times'][start:i+1]
            success_rolling.append(statistics.mean(window) if window else 0)
        
        plt.plot(success_rolling)
        plt.title(f'Rolling Avg Response Time (window={window_size})')
        plt.xlabel('Request Number')
        plt.ylabel('Response Time (ms)')
        plt.grid(True)
        
        # Plot 3: Status code distribution
        plt.subplot(2, 2, 3)
        status_counts = {}
        for code in self.metrics['status_codes']:
            status_counts[code] = status_counts.get(code, 0) + 1
        plt.bar([str(k) for k in status_counts.keys()], status_counts.values())
        plt.title('HTTP Status Code Distribution')
        plt.xlabel('Status Code')
        plt.ylabel('Count')
        
        # Plot 4: TTFB distribution
        plt.subplot(2, 2, 4)
        plt.hist([t for t in self.metrics['ttfb_values'] if t > 0], bins=20)
        plt.title('Time To First Byte Distribution')
        plt.xlabel('TTFB (ms)')
        plt.ylabel('Frequency')
        
        plt.tight_layout()
        plot_file = self.csv_file.replace('.csv', '_plot.png')
        plt.savefig(plot_file)
        print(f"Plot saved to: {plot_file}")
        plt.close()

def main():
    """Main function with argument parsing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTP Metrics Collector for DDoS Testing')
    parser.add_argument('url', help='Target URL (e.g., http://192.168.1.100/)')
    parser.add_argument('--interval', '-i', type=float, default=1.0, 
                       help='Request interval in seconds (default: 1.0)')
    parser.add_argument('--timeout', '-t', type=float, default=5.0,
                       help='Request timeout in seconds (default: 5.0)')
    parser.add_argument('--duration', '-d', type=float,
                       help='Duration to run in seconds')
    parser.add_argument('--requests', '-r', type=int,
                       help='Maximum number of requests to make')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    collector = HTTPMetricsCollector(
        target_url=args.url,
        interval=args.interval,
        timeout=args.timeout
    )
    
    collector.collect_metrics(
        duration_seconds=args.duration,
        max_requests=args.requests
    )

if __name__ == "__main__":
    main()