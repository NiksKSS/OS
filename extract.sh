#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 <image.img> <key> [output_dir]"
    exit 1
fi

IMAGE="$1"
KEY="$2"
OUTDIR="${3:-extracted}"

mkdir -p "$OUTDIR"

./secure_copy -list -image "$IMAGE" | while IFS=$'\t' read -r name size; do
    dirpart=$(dirname "$name")
    mkdir -p "$OUTDIR/$dirpart"
    echo "$name"
    ./secure_copy -get -key "$KEY" -image "$IMAGE" -out "$OUTDIR/$name" "$name" 2>/dev/null
done

echo "Saved to: $OUTDIR"
