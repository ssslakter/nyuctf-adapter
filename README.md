# NYU CTF → Harbor Adapter

Converts [NYU CTF Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) challenges
into [Harbor](https://harborframework.com) task format so you can run them with
`harbor run -p`.

## What it produces

For every challenge, the adapter writes one Harbor task directory:

```
<output-dir>/<task-id>/
├── task.toml          # Harbor config (name, category, timeouts)
├── instruction.md     # What the agent sees
├── environment/
│   ├── Dockerfile     # Agent container
│   ├── entrypoint.sh  # Server challenges: starts server in background
│   └── files/         # Static challenges: challenge files
├── solution/
│   └── solve.sh       # Oracle (writes known flag; replace with real solver)
└── tests/
    └── test.sh        # Checks /workspace/flag.txt against the real flag
```

## Two challenge types

| Type | Challenges | Dockerfile base | Notes |
|------|-----------|----------------|-------|
| **Static** | crypto, rev, forensics, most misc | `ubuntu:22.04` | Files copied into `/workspace/` |
| **Server** | pwn, web, some misc/crypto | `llmctf/<challenge-id>` | Server started in background via `entrypoint.sh` |

### Server challenges

Server challenges use the pre-built `llmctf/` images from Docker Hub as the
base image.  The `entrypoint.sh` starts the original server in the background
and waits for it to be ready before handing control to the agent.

The agent connects to `localhost:<port>` (port shown in `instruction.md`).

> **Note:** Docker must be able to pull `llmctf/` images at build time.
> Run `docker login` if you encounter auth errors.

## Installation

```bash
pip install -e .
```

Or without cloning Harbor's repo:

```bash
pip install nyuctf
# then run the adapter directly:
python -m nyu_ctf_adapter.main --output-dir ./my-dataset
```

## Usage

### Generate the full development split
```bash
python -m nyu_ctf_adapter.main \
    --output-dir ./dataset \
    --split development
```

### Only crypto + rev challenges
```bash
python -m nyu_ctf_adapter.main \
    --output-dir ./dataset \
    --category crypto rev
```

### Skip server challenges (no Docker pull needed)
```bash
python -m nyu_ctf_adapter.main \
    --output-dir ./dataset \
    --skip-server
```

### Full test split, limit to 20
```bash
python -m nyu_ctf_adapter.main \
    --output-dir ./dataset \
    --split test \
    --limit 20
```

### Specific task IDs
```bash
python -m nyu_ctf_adapter.main \
    --output-dir ./dataset \
    --task-ids 2021q-cry-bits,2022q-rev-whatisit
```

### Dry run (list tasks without writing)
```bash
python -m nyu_ctf_adapter.main --output-dir ./dataset --dry-run
```

## Running with Harbor

Once you have a dataset directory, point `harbor run` at it:

```bash
# Run with a local model via Ollama
harbor run \
    -p ./dataset \
    -a claude-code \
    -m your-model

# Run only static crypto challenges  
python -m nyu_ctf_adapter.main \
    --output-dir ./crypto-only \
    --category crypto --skip-server

harbor run -p ./crypto-only -a claude-code -m your-model
```

## Pushing to Harbor Hub

After generating and validating the dataset locally:

1. Set `HARBOR_API_KEY` in your environment
2. Run:
   ```bash
   harbor dataset push ./dataset --name nyu-ctf/development
   ```

Or follow the [Harbor publishing docs](https://harborframework.com/docs/datasets/publishing)
to open a PR to the `harbor-datasets` repo for official registry inclusion.

## Oracle solutions

The generated `solution/solve.sh` files write the known flag directly — useful
for checking that the environment is correct but not a real solver.

To replace them with actual solvers, look at the
[NYU CTF write-ups](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) that ship
with the dataset (each challenge directory often contains a `README.md` with
hints or a solver script).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir` | required | Where to write task directories |
| `--split` | `development` | `development` (57 tasks) or `test` (200 tasks) |
| `--category` | all | One or more of: `crypto rev forensics misc web pwn` |
| `--task-ids` | all | Comma-separated task IDs to generate |
| `--limit` | none | Stop after N tasks |
| `--overwrite` | false | Regenerate existing task directories |
| `--skip-server` | false | Skip challenges that need a server container |
| `--dry-run` | false | List tasks without writing |
