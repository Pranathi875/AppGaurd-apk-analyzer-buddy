/**
 * DEX reader: extracts class descriptors and a filtered subset of the string
 * pool. We deliberately do not decompile: signature-based capability and
 * library detection only needs type descriptors and referenced strings.
 *
 * Multidex packages routinely ship classes.dex .. classes14.dex. Every file is
 * scanned; work is chunked and yields to the event loop so the tab stays
 * responsive, and each file reports its own outcome instead of collapsing into
 * a single global "truncated" flag.
 */

import type { DexFacts, DexFileReport } from "./types";

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a]; // "dex\n"
/** Items processed between yields to the event loop. */
const CHUNK_SIZE = 20_000;
/** Distinct matched values retained; matching stops there, scanning does not. */
const MAX_MATCHES = 8_000;

export interface DexInput {
  name: string;
  bytes: Uint8Array;
}

export interface DexScanOptions {
  /** Lowercased tokens; a string is retained only when it contains one. */
  tokens: string[];
  /** Reports progress in the 0..1 range across all DEX files. */
  onProgress?: (fraction: number, fileName: string) => void;
}

export function isDex(bytes: Uint8Array): boolean {
  return DEX_MAGIC.every((byte, index) => bytes[index] === byte);
}

const yieldToUi = () =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });

export async function scanDex(inputs: DexInput[], options: DexScanOptions): Promise<DexFacts> {
  const matchedStrings = new Set<string>();
  const matchedClasses = new Set<string>();
  const packagePrefixes = new Set<string>();
  const files: DexFileReport[] = [];
  /** Checksums of already scanned DEX files, so duplicates are not rescanned. */
  const seenChecksums = new Set<number>();
  let classCount = 0;
  let parsedAny = false;
  let error: string | null = null;

  const tokens = options.tokens.map((token) => token.toLowerCase()).filter(Boolean);
  const totalBytes = inputs.reduce((sum, input) => sum + input.bytes.length, 0) || 1;
  let processedBytes = 0;

  for (const input of inputs) {
    const { name, bytes } = input;
    try {
      if (!isDex(bytes)) {
        files.push({ name, status: "SKIPPED", classCount: 0, stringCount: 0, reason: "Not a DEX container" });
        processedBytes += bytes.length;
        continue;
      }

      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const checksum = view.getUint32(8, true);
      if (seenChecksums.has(checksum)) {
        files.push({
          name,
          status: "SKIPPED",
          classCount: 0,
          stringCount: 0,
          reason: "Identical to an already scanned DEX file (same checksum)",
        });
        processedBytes += bytes.length;
        continue;
      }
      seenChecksums.add(checksum);

      const stringIdsSize = view.getUint32(56, true);
      const stringIdsOff = view.getUint32(60, true);
      const typeIdsSize = view.getUint32(64, true);
      const typeIdsOff = view.getUint32(68, true);
      parsedAny = true;

      const readStringAt = (index: number): string | null => {
        const pointerOffset = stringIdsOff + index * 4;
        if (pointerOffset + 4 > bytes.length) return null;
        let dataOffset = view.getUint32(pointerOffset, true);
        const size = readUleb128(bytes, dataOffset);
        dataOffset = size.next;
        let end = dataOffset;
        while (end < bytes.length && bytes[end] !== 0) end += 1;
        return decodeMutf8(bytes.subarray(dataOffset, end));
      };

      // --- string pool ---------------------------------------------------
      for (let i = 0; i < stringIdsSize; i += 1) {
        if (i > 0 && i % CHUNK_SIZE === 0) {
          options.onProgress?.(
            Math.min(1, (processedBytes + (bytes.length * i) / Math.max(1, stringIdsSize + typeIdsSize)) / totalBytes),
            name,
          );
          await yieldToUi();
        }
        if (matchedStrings.size >= MAX_MATCHES) break;
        const value = readStringAt(i);
        if (!value || value.length < 4 || value.length > 300) continue;
        const lower = value.toLowerCase();
        if (tokens.some((token) => lower.includes(token))) matchedStrings.add(value);
      }

      // --- type descriptors ------------------------------------------------
      classCount += typeIdsSize;
      for (let i = 0; i < typeIdsSize; i += 1) {
        if (i > 0 && i % CHUNK_SIZE === 0) await yieldToUi();
        const pointerOffset = typeIdsOff + i * 4;
        if (pointerOffset + 4 > bytes.length) break;
        const stringIndex = view.getUint32(pointerOffset, true);
        const descriptor = readStringAt(stringIndex);
        if (!descriptor || !descriptor.startsWith("L")) continue;
        const dotted = descriptor.slice(1, -1).replace(/\//g, ".");
        const parts = dotted.split(".");
        if (parts.length >= 3) packagePrefixes.add(parts.slice(0, 3).join("."));
        const lower = dotted.toLowerCase();
        if (matchedClasses.size < MAX_MATCHES && tokens.some((token) => lower.includes(token))) {
          matchedClasses.add(dotted);
        }
      }

      files.push({ name, status: "ANALYZED", classCount: typeIdsSize, stringCount: stringIdsSize, reason: null });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Unknown DEX parse failure";
      error = message;
      files.push({ name, status: "FAILED", classCount: 0, stringCount: 0, reason: message });
    }

    processedBytes += bytes.length;
    options.onProgress?.(Math.min(1, processedBytes / totalBytes), name);
    await yieldToUi();
  }

  const analyzed = files.filter((file) => file.status === "ANALYZED");
  const failed = files.filter((file) => file.status === "FAILED");

  return {
    parsed: parsedAny,
    dexFiles: inputs.length,
    analyzedFiles: analyzed.map((file) => file.name),
    files,
    classCount,
    packagePrefixes: [...packagePrefixes].sort().slice(0, 500),
    matchedStrings: [...matchedStrings].sort(),
    matchedClasses: [...matchedClasses].sort(),
    // Truncation now means "a DEX file could not be completed", not "we chose
    // to stop early".
    truncated: failed.length > 0,
    error,
  };
}

export function readUleb128(bytes: Uint8Array, offset: number): { value: number; next: number } {
  let result = 0;
  let shift = 0;
  let cursor = offset;
  for (let i = 0; i < 5; i += 1) {
    const byte = bytes[cursor] ?? 0;
    cursor += 1;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value: result >>> 0, next: cursor };
}

/** MUTF-8 is UTF-8 for the ASCII/BMP range we care about. */
function decodeMutf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
