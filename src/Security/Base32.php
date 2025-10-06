<?php
declare(strict_types=1);

namespace AuthKit\Security;

final class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $data): string
    {
        $alphabet = self::ALPHABET;
        $binary = '';
        foreach (str_split($data) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $chunks = str_split($binary, 5);
        $output = '';
        foreach ($chunks as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= $alphabet[bindec($chunk)];
        }
        $padLen = (8 - (int)ceil(strlen($data) * 8 / 5)) % 8;
        return $output . str_repeat('=', $padLen);
    }

    public static function decode(string $input): string
    {
        $alphabet = self::ALPHABET;
        $input = rtrim(strtoupper($input), '=');
        $binary = '';
        foreach (str_split($input) as $char) {
            $pos = strpos($alphabet, $char);
            if ($pos === false) { continue; }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $bytes = str_split($binary, 8);
        $output = '';
        foreach ($bytes as $byte) {
            if (strlen($byte) === 8) {
                $output .= chr(bindec($byte));
            }
        }
        return $output;
    }
}


