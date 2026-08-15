<?php

declare(strict_types=1);

namespace FoxyDB\Sql;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\Identifiers;

final class Lexer
{
    private const MAXIMUM_SQL_BYTES = 16_777_216;
    private const MAXIMUM_TOKENS = 1_000_000;
    private int $offset = 0;
    private int $line = 1;
    private int $column = 1;
    private int $length;

    public function __construct(private readonly string $sql)
    {
        $this->length = strlen($sql);
        if ($this->length > self::MAXIMUM_SQL_BYTES) {
            throw new FoxyException('SQL text exceeds the 16 MiB limit.', 'SQL_TOO_LARGE');
        }
    }

    public function tokenize(): array
    {
        $tokens = [];
        while (true) {
            if (count($tokens) >= self::MAXIMUM_TOKENS) {
                throw $this->syntaxError('SQL statement contains too many tokens.');
            }
            $this->skipIgnored();
            if ($this->offset >= $this->length) {
                $tokens[] = new Token('EOF', null, $this->offset, $this->line, $this->column);
                return $tokens;
            }

            $offset = $this->offset;
            $line = $this->line;
            $column = $this->column;
            $character = $this->sql[$this->offset];

            if (($character === 'x' || $character === 'X') && $this->peek(1) === "'") {
                $tokens[] = new Token('BINARY', $this->readHexLiteral(), $offset, $line, $column);
                continue;
            }
            if ($character === "'") {
                $tokens[] = new Token('STRING', $this->readString(), $offset, $line, $column);
                continue;
            }
            if ($character === '`' || $character === '"') {
                $tokens[] = new Token(
                    'IDENTIFIER',
                    $this->readQuotedIdentifier($character),
                    $offset,
                    $line,
                    $column,
                    true,
                );
                continue;
            }
            if (Identifiers::isStartByte(ord($character))) {
                $tokens[] = new Token('IDENTIFIER', $this->readIdentifier(), $offset, $line, $column);
                continue;
            }
            if (ctype_digit($character) || ($character === '.' && ctype_digit($this->peek(1)))) {
                $tokens[] = new Token('NUMBER', $this->readNumber(), $offset, $line, $column);
                continue;
            }
            if ($character === '?') {
                $this->advance();
                $tokens[] = new Token('PARAMETER', null, $offset, $line, $column);
                continue;
            }
            if ($character === ':' && Identifiers::isStartByte(ord($this->peek(1)))) {
                $this->advance();
                $tokens[] = new Token('PARAMETER', $this->readIdentifier(), $offset, $line, $column);
                continue;
            }

            $pair = $character . $this->peek(1);
            if (in_array($pair, ['<=', '>=', '<>', '!='], true)) {
                $this->advance();
                $this->advance();
                $tokens[] = new Token('SYMBOL', $pair, $offset, $line, $column);
                continue;
            }
            if (str_contains('(),;.*=<>+-/%', $character)) {
                $this->advance();
                $tokens[] = new Token('SYMBOL', $character, $offset, $line, $column);
                continue;
            }

            throw $this->syntaxError("Unexpected character: {$character}", $offset, $line, $column);
        }
    }

    private function skipIgnored(): void
    {
        while ($this->offset < $this->length) {
            $character = $this->sql[$this->offset];
            if (ctype_space($character)) {
                $this->advance();
                continue;
            }
            if (($character === '-' && $this->peek(1) === '-') || $character === '#') {
                while ($this->offset < $this->length && $this->sql[$this->offset] !== "\n") {
                    $this->advance();
                }
                continue;
            }
            if ($character === '/' && $this->peek(1) === '*') {
                $startOffset = $this->offset;
                $startLine = $this->line;
                $startColumn = $this->column;
                $this->advance();
                $this->advance();
                while ($this->offset < $this->length
                    && !($this->sql[$this->offset] === '*' && $this->peek(1) === '/')) {
                    $this->advance();
                }
                if ($this->offset >= $this->length) {
                    throw $this->syntaxError('Unterminated block comment.', $startOffset, $startLine, $startColumn);
                }
                $this->advance();
                $this->advance();
                continue;
            }
            return;
        }
    }

    private function readIdentifier(): string
    {
        $start = $this->offset;
        while ($this->offset < $this->length
            && Identifiers::isContinueByte(ord($this->sql[$this->offset]))) {
            $this->advance();
        }
        return substr($this->sql, $start, $this->offset - $start);
    }

    private function readQuotedIdentifier(string $delimiter): string
    {
        $this->advance();
        $value = '';
        while ($this->offset < $this->length) {
            $character = $this->sql[$this->offset];
            if ($character === $delimiter) {
                if ($this->peek(1) === $delimiter) {
                    $value .= $delimiter;
                    $this->advance();
                    $this->advance();
                    continue;
                }
                $this->advance();
                if ($value === '') {
                    throw $this->syntaxError('An identifier cannot be empty.');
                }
                return $value;
            }
            if ($character === "\0") {
                throw $this->syntaxError('An identifier cannot contain a null byte.');
            }
            $value .= $character;
            $this->advance();
        }
        throw $this->syntaxError('Unterminated quoted identifier.');
    }

    private function readString(): string
    {
        $this->advance();
        $value = '';
        while ($this->offset < $this->length) {
            $character = $this->sql[$this->offset];
            if ($character === "'") {
                if ($this->peek(1) === "'") {
                    $value .= "'";
                    $this->advance();
                    $this->advance();
                    continue;
                }
                $this->advance();
                return $value;
            }
            if ($character === '\\') {
                $this->advance();
                if ($this->offset >= $this->length) {
                    throw $this->syntaxError('Unterminated string literal.');
                }
                $escaped = $this->sql[$this->offset];
                $value .= match ($escaped) {
                    '0' => "\0",
                    'n' => "\n",
                    'r' => "\r",
                    't' => "\t",
                    'b' => "\x08",
                    'Z' => "\x1a",
                    '%', '_' => '\\' . $escaped,
                    default => $escaped,
                };
                $this->advance();
                continue;
            }
            $value .= $character;
            $this->advance();
        }
        throw $this->syntaxError('Unterminated string literal.');
    }

    private function readHexLiteral(): string
    {
        $this->advance();
        $this->advance();
        $hex = '';
        while ($this->offset < $this->length && $this->sql[$this->offset] !== "'") {
            $hex .= $this->sql[$this->offset];
            $this->advance();
        }
        if ($this->offset >= $this->length) {
            throw $this->syntaxError('Unterminated binary literal.');
        }
        $this->advance();
        if (strlen($hex) % 2 !== 0 || ($hex !== '' && !ctype_xdigit($hex))) {
            throw $this->syntaxError('A binary literal must contain pairs of hexadecimal digits.');
        }
        $value = hex2bin($hex);
        if ($value === false) {
            throw $this->syntaxError('Invalid binary literal.');
        }
        return $value;
    }

    private function readNumber(): string
    {
        $start = $this->offset;
        if ($this->sql[$this->offset] === '.') {
            $this->advance();
            while (ctype_digit($this->peek())) {
                $this->advance();
            }
        } else {
            while (ctype_digit($this->peek())) {
                $this->advance();
            }
            if ($this->peek() === '.') {
                $this->advance();
                while (ctype_digit($this->peek())) {
                    $this->advance();
                }
            }
        }
        if (strtolower($this->peek()) === 'e') {
            $this->advance();
            if ($this->peek() === '+' || $this->peek() === '-') {
                $this->advance();
            }
            if (!ctype_digit($this->peek())) {
                throw $this->syntaxError('Invalid numeric exponent.');
            }
            while (ctype_digit($this->peek())) {
                $this->advance();
            }
        }
        return substr($this->sql, $start, $this->offset - $start);
    }

    private function peek(int $distance = 0): string
    {
        $position = $this->offset + $distance;
        return $position >= 0 && $position < $this->length ? $this->sql[$position] : "\0";
    }

    private function advance(): void
    {
        if ($this->offset >= $this->length) {
            return;
        }
        if ($this->sql[$this->offset] === "\n") {
            $this->line++;
            $this->column = 1;
        } else {
            $this->column++;
        }
        $this->offset++;
    }

    private function syntaxError(
        string $message,
        ?int $offset = null,
        ?int $line = null,
        ?int $column = null,
    ): FoxyException {
        return new FoxyException($message, 'SQL_SYNTAX', [
            'offset' => $offset ?? $this->offset,
            'line' => $line ?? $this->line,
            'column' => $column ?? $this->column,
        ]);
    }
}
