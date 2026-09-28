#!/usr/bin/env python3
"""Flag request bursts and shared-port probes from a live tshark capture."""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone


def positive_int(value: str) -> int:
	number = int(value)
	if number < 1:
		raise argparse.ArgumentTypeError("must be at least 1")
	return number


def positive_float(value: str) -> float:
	number = float(value)
	if number <= 0:
		raise argparse.ArgumentTypeError("must be greater than 0")
	return number


def parse_packet(line: str) -> tuple[float, str, str, str, str] | None:
	fields = line.rstrip("\r\n").split("\t")
	if len(fields) < 9:
		return None

	try:
		timestamp = float(fields[0])
	except ValueError:
		return None

	source_ip = fields[1] or fields[2]
	destination_ip = fields[3] or fields[4]
	tcp_destination_port = fields[5]
	udp_destination_port = fields[6]
	syn_flag = fields[7]
	ack_flag = fields[8]

	if not source_ip or not destination_ip:
		return None

	if tcp_destination_port:
		try:
			is_syn = int(syn_flag, 0) != 0
			is_ack = int(ack_flag, 0) != 0
		except ValueError:
			return None
		if not is_syn or is_ack:
			return None
		destination_port = tcp_destination_port
		protocol = "TCP SYN"
	elif udp_destination_port:
		destination_port = udp_destination_port
		protocol = "UDP"
	else:
		return None

	return timestamp, protocol, source_ip, destination_ip, destination_port


def print_table_header() -> None:
	columns = ("TIME UTC", "PROTO", "SOURCE IP", "DESTINATION IP", "DST PORT")
	widths = (15, 7, 39, 39, 8)
	print(" | ".join(column.ljust(width) for column, width in zip(columns, widths)), flush=True)
	print("-+-".join("-" * width for width in widths), flush=True)


def monitor(args: argparse.Namespace) -> int:
	command = [
		args.tshark,
		"-l",
		"-n",
		"-i",
		args.interface,
		"-f",
		args.capture_filter,
		"-T",
		"fields",
		"-E",
		"separator=\\t",
		"-E",
		"occurrence=f",
	]
	for field in (
		"frame.time_epoch",
		"ip.src",
		"ipv6.src",
		"ip.dst",
		"ipv6.dst",
		"tcp.dstport",
		"udp.dstport",
		"tcp.flags.syn",
		"tcp.flags.ack",
	):
		command.extend(("-e", field))

	try:
		process = subprocess.Popen(
			command,
			stdout=subprocess.PIPE,
			text=True,
			encoding="utf-8",
			errors="replace",
			bufsize=1,
		)
	except FileNotFoundError:
		print(
			f"Could not find {args.tshark!r}. Install Wireshark/tshark and ensure it is on PATH.",
			file=sys.stderr,
		)
		return 2
	except OSError as error:
		print(f"Could not start tshark: {error}", file=sys.stderr)
		return 2

	assert process.stdout is not None
	csv_file = None
	csv_writer = None
	if args.csv_log:
		try:
			needs_header = not os.path.exists(args.csv_log) or os.path.getsize(args.csv_log) == 0
			csv_file = open(args.csv_log, "a", newline="", encoding="utf-8", buffering=1)
		except OSError as error:
			process.terminate()
			process.wait()
			process.stdout.close()
			print(f"Could not open CSV log {args.csv_log!r}: {error}", file=sys.stderr)
			return 2
		csv_writer = csv.writer(csv_file)
		if needs_header:
			csv_writer.writerow(("timestamp_utc", "protocol", "source_ip", "destination_ip", "destination_port"))

	rate_events: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)
	source_events: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)
	last_alert: dict[tuple[str, ...], float] = {}
	packet_count = 0
	stopped_by_user = False
	print(
		f"Monitoring {args.interface}; window={args.window:g}s, "
		f"rate threshold={args.request_threshold}, "
		f"distinct-source threshold={args.source_threshold}. Press Ctrl+C to stop.",
		flush=True,
	)
	print_table_header()

	try:
		for line in process.stdout:
			packet = parse_packet(line)
			if packet is None:
				continue

			timestamp, protocol, source_ip, destination_ip, destination_port = packet
			packet_count += 1
			time_utc = datetime.fromtimestamp(timestamp, timezone.utc)
			table_row = (
				time_utc.strftime("%H:%M:%S.%f")[:-3],
				protocol,
				source_ip,
				destination_ip,
				destination_port,
			)
			print(" | ".join(value.ljust(width) for value, width in zip(table_row, (15, 7, 39, 39, 8))), flush=True)
			if csv_writer is not None:
				csv_writer.writerow((time_utc.isoformat(timespec="milliseconds"), *table_row[1:]))

			cutoff = timestamp - args.window
			target = (destination_ip, destination_port)
			rate_key = (source_ip, destination_ip, destination_port)

			rate_window = rate_events[rate_key]
			while rate_window and rate_window[0] < cutoff:
				rate_window.popleft()
			rate_window.append(timestamp)

			sources = source_events[target]
			for old_source, last_seen in list(sources.items()):
				if last_seen < cutoff:
					del sources[old_source]
			sources[source_ip] = timestamp

			if len(rate_window) >= args.request_threshold:
				alert_key = ("rate", *rate_key)
				if timestamp - last_alert.get(alert_key, float("-inf")) >= args.cooldown:
					print(
						f"ALERT [request burst] {source_ip} -> "
						f"{destination_ip}:{destination_port}: "
						f"{len(rate_window)} request-like packets in {args.window:g}s",
						flush=True,
					)
					last_alert[alert_key] = timestamp

			if len(sources) >= args.source_threshold:
				alert_key = ("sources", *target)
				if timestamp - last_alert.get(alert_key, float("-inf")) >= args.cooldown:
					sample = ", ".join(sorted(sources)[:8])
					suffix = " ..." if len(sources) > 8 else ""
					print(
						f"ALERT [shared-port probe] {len(sources)} source IPs "
						f"targeted {destination_ip}:{destination_port} in "
						f"{args.window:g}s ({sample}{suffix})",
						flush=True,
					)
					last_alert[alert_key] = timestamp

			if packet_count % 1000 == 0:
				active_rates = set(rate_events)
				for stale_key in active_rates:
					events = rate_events[stale_key]
					while events and events[0] < cutoff:
						events.popleft()
					if not events:
						del rate_events[stale_key]
				for stale_key, alert_time in list(last_alert.items()):
					if alert_time < cutoff - args.cooldown:
						del last_alert[stale_key]
	except KeyboardInterrupt:
		stopped_by_user = True
		print("\nCapture stopped.", flush=True)
	finally:
		if process.poll() is None:
			process.terminate()
			try:
				process.wait(timeout=2)
			except subprocess.TimeoutExpired:
				process.kill()
				process.wait()
		process.stdout.close()
		if csv_file is not None:
			csv_file.close()

	return 0 if stopped_by_user else process.returncode or 0


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description=(
			"Monitor TCP connection attempts and UDP packets with tshark. "
			"Alerts are heuristics, not proof of malicious activity."
		)
	)
	parser.add_argument("-i", "--interface", help="capture interface, such as eth0")
	parser.add_argument("--list-interfaces", action="store_true", help="show tshark interfaces and exit")
	parser.add_argument("--tshark", default="tshark", help="tshark executable (default: tshark)")
	parser.add_argument("--capture-filter", default="tcp or udp", help="libpcap capture filter")
	parser.add_argument("--csv-log", help="append captured request rows to a CSV file")
	parser.add_argument("--window", type=positive_float, default=10.0, help="sliding window in seconds")
	parser.add_argument(
		"--request-threshold",
		type=positive_int,
		default=30,
		help="TCP SYN or UDP packets from one source to one target port per window",
	)
	parser.add_argument(
		"--source-threshold",
		type=positive_int,
		default=8,
		help="distinct source IPs targeting one destination port per window",
	)
	parser.add_argument("--cooldown", type=positive_float, default=30.0, help="seconds between repeat alerts")
	return parser


def main() -> int:
	parser = build_parser()
	args = parser.parse_args()

	if args.list_interfaces:
		try:
			return subprocess.run([args.tshark, "-D"], check=False).returncode
		except FileNotFoundError:
			print(f"Could not find {args.tshark!r}. Install Wireshark/tshark and ensure it is on PATH.", file=sys.stderr)
			return 2

	if not args.interface:
		parser.error("--interface is required unless --list-interfaces is used")
	return monitor(args)


if __name__ == "__main__":
	raise SystemExit(main())
