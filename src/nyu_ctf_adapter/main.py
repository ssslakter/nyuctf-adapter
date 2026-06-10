"""
CLI entry point.

Usage:
    python -m nyu_ctf_adapter.main --output-dir ./dataset

Required Harbor flags:
    --output-dir   Where to write task directories
    --limit        Max number of tasks to generate
    --overwrite    Regenerate tasks that already exist
    --task-ids     Comma-separated list of specific task IDs

Extra flags:
    --split        "development" (default) or "test"
    --category     One or more of: crypto rev forensics misc web pwn
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapter import iter_challenges, generate_task

VALID_CATEGORIES = {"crypto", "rev", "forensics", "misc", "web", "pwn"}
VALID_SPLITS = {"development", "test"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="nyu-ctf-adapter",
        description="Generate Harbor task directories from NYU CTF Bench.",
    )
    p.add_argument(
        "--output-dir", "-o",
        required=True,
        help="Root directory where task folders will be written.",
    )
    p.add_argument(
        "--split",
        default="development",
        choices=list(VALID_SPLITS),
        help="NYU CTF split to convert (default: development).",
    )
    p.add_argument(
        "--category",
        nargs="+",
        choices=list(VALID_CATEGORIES),
        metavar="CAT",
        help="Only convert challenges from these categories.",
    )
    p.add_argument(
        "--task-ids",
        help="Comma-separated Harbor task IDs to (re)generate; skips all others.",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after generating this many tasks.",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Regenerate task directories that already exist.",
    )
    p.add_argument(
        "--skip-server",
        action="store_true",
        help="Skip challenges that require a server container.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="List tasks that would be generated without writing anything.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    output_dir = Path(args.output_dir).expanduser().resolve()

    task_ids: list[str] | None = None
    if args.task_ids:
        task_ids = [t.strip() for t in args.task_ids.split(",") if t.strip()]

    categories: list[str] | None = args.category  # None means all

    generated = 0
    skipped = 0
    errors = 0

    print(f"[nyu-ctf-adapter] split={args.split}  output={output_dir}")
    if categories:
        print(f"[nyu-ctf-adapter] filtering categories: {categories}")
    if task_ids:
        print(f"[nyu-ctf-adapter] filtering task IDs: {task_ids}")

    for harbor_id, chal in iter_challenges(
        split=args.split,
        categories=categories,
        task_ids=task_ids,
    ):
        if args.limit is not None and generated >= args.limit:
            break

        if args.skip_server and chal.container:
            print(f"[SKIP-SERVER] {harbor_id}")
            skipped += 1
            continue

        if args.dry_run:
            server_marker = " [server]" if chal.container else ""
            print(f"  {harbor_id}  ({chal.category}){server_marker}")
            generated += 1
            continue

        try:
            task_path = generate_task(
                harbor_id,
                chal,
                output_dir,
                overwrite=args.overwrite,
            )
            status = "OVERWRITE" if args.overwrite and task_path.exists() else "OK"
            server_marker = " [server]" if chal.container else ""
            print(f"[{status}] {harbor_id}  ({chal.category}){server_marker}  → {task_path}")
            generated += 1
        except Exception as exc:
            print(f"[ERROR] {harbor_id}: {exc}", file=sys.stderr)
            errors += 1

    print(
        f"\n[nyu-ctf-adapter] done: {generated} generated, "
        f"{skipped} skipped, {errors} errors"
    )
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
