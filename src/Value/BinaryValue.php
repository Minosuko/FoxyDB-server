<?php

declare(strict_types=1);

namespace FoxyDB\Value;

final readonly class BinaryValue
{
    public function __construct(public string $bytes)
    {
    }

    public static function fromBase64(string $value): self
    {
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64 binary value.');
        }
        return new self($decoded);
    }

    public function length(): int
    {
        return strlen($this->bytes);
    }

    public function toBase64(): string
    {
        return base64_encode($this->bytes);
    }
}
