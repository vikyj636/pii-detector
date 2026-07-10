#!/usr/bin/env python3
"""Download the GLiNER2 model snapshot at Docker build time.

Runs only inside `docker build` (see Dockerfile). At runtime the app loads the
weights from the baked-in local directory and never touches the network.
"""
import argparse

from huggingface_hub import snapshot_download


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="fastino/gliner2-privacy-filter-PII-multi")
    parser.add_argument("--dest", default="/opt/model")
    args = parser.parse_args()
    path = snapshot_download(repo_id=args.model, local_dir=args.dest)
    print(f"model snapshot written to {path}")


if __name__ == "__main__":
    main()
