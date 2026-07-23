<?php

declare(strict_types=1);

namespace FoxyDB\Support;

use FoxyDB\Value\BinaryValue;
use FoxyDB\Value\ChunkedValue;

final class MemoryCache
{
    private const ENTRY_OVERHEAD_BYTES = 96;

    private array $entries = [];
    private int $usedBytes = 0;
    private int $hits = 0;
    private int $misses = 0;

    public function __construct(private int $maximumBytes = 0)
    {
    }

    public function get(string $key): mixed
    {
        if (!isset($this->entries[$key])) {
            $this->misses++;
            return null;
        }
        $entry = $this->entries[$key];
        unset($this->entries[$key]);
        $this->entries[$key] = $entry;
        $this->hits++;
        return $entry['value'];
    }

    public function put(string $key, mixed $value, ?int $bytes = null): bool
    {
        if ($this->maximumBytes === 0) {
            return false;
        }
        $bytes = ($bytes ?? self::estimateBytes($value)) + self::ENTRY_OVERHEAD_BYTES + strlen($key);
        if ($bytes < 1 || $bytes > $this->maximumBytes) {
            return false;
        }
        if (isset($this->entries[$key])) {
            $this->usedBytes -= $this->entries[$key]['bytes'];
            unset($this->entries[$key]);
        }
        $this->entries[$key] = ['value' => $value, 'bytes' => $bytes];
        $this->usedBytes += $bytes;
        $this->trim();
        return true;
    }

    public function setMaximumBytes(int $maximumBytes): void
    {
        $this->maximumBytes = max(0, $maximumBytes);
        $this->trim();
    }

    public function clear(): void
    {
        $this->entries = [];
        $this->usedBytes = 0;
    }

    public function statistics(): array
    {
        return [
            'maximum_bytes' => $this->maximumBytes,
            'used_bytes' => $this->usedBytes,
            'entries' => count($this->entries),
            'hits' => $this->hits,
            'misses' => $this->misses,
        ];
    }

    public static function estimateBytes(mixed $value, int $depth = 0): int
    {
        if ($depth > 32) {
            return 64;
        }
        if ($value === null || is_bool($value) || is_int($value) || is_float($value)) {
            return 16;
        }
        if (is_string($value)) {
            return 32 + strlen($value);
        }
        if ($value instanceof BinaryValue) {
            return 48 + strlen($value->bytes);
        }
        if ($value instanceof ChunkedValue) {
            return 128 + count($value->chunks) * 96;
        }
        if (is_array($value)) {
            $bytes = 32;
            foreach ($value as $key => $item) {
                $bytes += 32 + (is_string($key) ? strlen($key) : 8);
                $bytes += self::estimateBytes($item, $depth + 1);
            }
            return $bytes;
        }
        return 128;
    }

    private function trim(): void
    {
        while ($this->usedBytes > $this->maximumBytes && $this->entries !== []) {
            $key = array_key_first($this->entries);
            $this->usedBytes -= $this->entries[$key]['bytes'];
            unset($this->entries[$key]);
        }
    }
}
