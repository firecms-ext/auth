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

interface StatefulGuardInterface extends GuardInterface
{
    /**
     * Attempt to authenticate a user using the given credentials.
     * @return bool|mixed
     */
    public function attempt(array $credentials = [], bool $remember = false): mixed;

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool;

    /**
     * Log a user into the application.
     *
     * @return mixed|void
     */
    public function login(AuthenticateInterface $user, bool $remember = false);

    /**
     * Log the given user ID into the application.
     */
    public function loginUsingId(string|int $id, bool $remember = false): ?AuthenticateInterface;

    /**
     * Log the given user ID into the application without sessions or cookies.
     */
    public function onceUsingId(string|int $id): bool|AuthenticateInterface;

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     */
    public function viaRemember(): bool;

    /**
     * Log the user out of the application.
     */
    public function logout(): void;
}
