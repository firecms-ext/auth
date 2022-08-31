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

interface UserProviderInterface
{
    /**
     * Retrieve a user by their unique identifier.
     */
    public function retrieveById(int|string $identifier): ?AuthenticateInterface;

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     */
    public function retrieveByToken(int|string $identifier, string $token): ?AuthenticateInterface;

    /**
     * Update the "remember me" token for the given user in storage.
     */
    public function updateRememberToken(AuthenticateInterface $user, string $token): void;

    /**
     * Retrieve a user by the given credentials.
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticateInterface;

    /**
     * Validate a user against the given credentials.
     */
    public function validateCredentials(AuthenticateInterface $user, array $credentials): bool;
}
