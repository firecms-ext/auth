<?php

declare(strict_types=1);
/**
 * This file is part of FirecmsExt Auth.
 *
 * @link     https://www.klmis.cn
 * @document https://www.klmis.cn
 * @contact  zhimengxingyun@klmis.cn
 * @license  https://github.com/firecms-ext/auth/blob/master/LICENSE
 */
namespace FirecmsExt\Auth;

use Hyperf\Utils\Str;

class Recalled
{
    /**
     * The "recalled" / "remember me" cookie string.
     */
    protected string $recalled;

    /**
     * Create a new recalled instance.
     */
    public function __construct(string $recalled)
    {
        $this->recalled = @unserialize($recalled, ['allowed_classes' => false]) ?: $recalled;
    }

    /**
     * Get the user ID from the recalled.
     */
    public function id(): string
    {
        return explode('|', $this->recalled, 3)[0];
    }

    /**
     * Get the "remember token" token from the recalled.
     */
    public function token(): string
    {
        return explode('|', $this->recalled, 3)[1];
    }

    /**
     * Get the password from the recalled.
     */
    public function hash(): string
    {
        return explode('|', $this->recalled, 3)[2];
    }

    /**
     * Determine if the recalled is valid.
     */
    public function valid(): bool
    {
        return $this->properString() && $this->hasAllSegments();
    }

    /**
     * Determine if the recalled is an invalid string.
     */
    protected function properString(): bool
    {
        return Str::contains($this->recalled, '|');
    }

    /**
     * Determine if the recalled has all segments.
     */
    protected function hasAllSegments(): bool
    {
        $segments = explode('|', $this->recalled);

        return count($segments) === 3 && trim($segments[0]) !== '' && trim($segments[1]) !== '';
    }
}
