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

interface StatelessGuardInterface extends GuardInterface
{
    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     */
    public function attempt(array $credentials = []): bool;

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool;

    /**
     * Log a user into the application, create a token for the user.
     */
    public function login(AuthenticateInterface $user): bool;

    /**
     * Log the given user ID into the application.
     *
     * @return false|mixed
     */
    public function loginUsingId(int|string $id): mixed;

    /**
     * Log the given user ID into the application without sessions or cookies.
     */
    public function onceUsingId(int|string $id): bool;

    /**
     * Log the user out of the application, thus invalidating the token.
     */
    public function logout(bool $forceForever = false);

    /**
     * Refresh the token.
     */
    public function refresh(bool $forceForever = false): mixed;

    /**
     * Invalidate the token.
     */
    public function invalidate(bool $forceForever = false): mixed;
}
