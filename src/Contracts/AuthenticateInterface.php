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
namespace FirecmsExt\Auth\Contracts;

interface AuthenticateInterface
{
    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string;

    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): ?string;

    /**
     * Get the password for the user.
     */
    public function getAuthPassword(): ?string;

    /**
     * Get the token value for the "remember me" session.
     */
    public function getRememberToken(): ?string;

    /**
     * Set the token value for the "remember me" session.
     */
    public function setRememberToken(string $value);

    /**
     * Get the column name for the "remember me" token.
     */
    public function getRememberTokenName(): ?string;
}
