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

use FirecmsExt\Auth\Contracts\AuthenticateInterface as UserContract;

class GenericUser implements UserContract
{
    /**
     * All the user's attributes.
     */
    protected array $attributes;

    /**
     * Create a new generic User object.
     */
    public function __construct(array $attributes)
    {
        $this->attributes = $attributes;
    }

    /**
     * Dynamically access the user's attributes.
     *
     * @return mixed
     */
    public function __get(string $key)
    {
        return $this->attributes[$key];
    }

    /**
     * Dynamically set an attribute on the user.
     */
    public function __set(string $key, mixed $value)
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Dynamically check if a value is set on the user.
     */
    public function __isset(string $key): bool
    {
        return isset($this->attributes[$key]);
    }

    /**
     * Dynamically unset a value on the user.
     */
    public function __unset(string $key): void
    {
        unset($this->attributes[$key]);
    }

    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): int|string|null
    {
        return $this->attributes[$this->getAuthIdentifierName()];
    }

    /**
     * Get the password for the user.
     */
    public function getAuthPassword(): ?string
    {
        return $this->attributes['password'];
    }

    /**
     * Get the "remember me" token value.
     */
    public function getRememberToken(): ?string
    {
        return $this->attributes[$this->getRememberTokenName()];
    }

    /**
     * Set the "remember me" token value.
     */
    public function setRememberToken(string $value)
    {
        $this->attributes[$this->getRememberTokenName()] = $value;
    }

    /**
     * Get the column name for the "remember me" token.
     */
    public function getRememberTokenName(): ?string
    {
        return 'remember_token';
    }
}
