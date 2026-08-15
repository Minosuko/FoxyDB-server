<?php

declare(strict_types=1);

namespace FoxyDB\Support;

use FoxyDB\Exception\FoxyException;

/**
 * Identifier byte rules and deterministic case folding.
 *
 * Bare identifiers accept letters, digits, underscores, and dollar signs and
 * also any UTF-8 byte sequence so non-ASCII names are first-class. Every
 * identifier folds to lowercase with a UTF-8-aware, locale-independent
 * transform, so lookups stay case-insensitive for ASCII and non-ASCII names.
 * Quoted identifiers are validated as UTF-8 and folded by the same rule.
 */
final class Identifiers
{
    /** True when the byte can start a bare (unquoted) identifier. */
    public static function isStartByte(int $byte): bool
    {
        return ($byte >= 0x41 && $byte <= 0x5A)
            || ($byte >= 0x61 && $byte <= 0x7A)
            || $byte === 0x5F
            || $byte >= 0x80;
    }

    /** True when the byte may continue a bare identifier. */
    public static function isContinueByte(int $byte): bool
    {
        return self::isStartByte($byte)
            || ($byte >= 0x30 && $byte <= 0x39)
            || $byte === 0x24;
    }

    /**
     * Validates and folds an identifier for engine storage and lookup.
     *
     * The fold is applied to quoted and bare names alike: a name has exactly
     * one canonical spelling regardless of how it was written in SQL.
     */
    public static function normalize(string $name): string
    {
        if ($name === '') {
            throw new FoxyException('An identifier cannot be empty.', 'SQL_SYNTAX');
        }
        if (!mb_check_encoding($name, 'UTF-8')) {
            throw new FoxyException('An identifier must be valid UTF-8 text.', 'SQL_SYNTAX');
        }
        return mb_strtolower($name, 'UTF-8');
    }
}