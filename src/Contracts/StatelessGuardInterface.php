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

use FirecmsExt\Jwt\Jwt;

/**
 * Token 登录接口.
 */
interface StatelessGuardInterface extends GuardInterface
{
    /**
     * 尝试使用给定的凭证对用户进行身份验证。
     */
    public function attempt(array $credentials = []): bool;

    /**
     * 将用户登录到没有会话或cookie的应用程序。
     */
    public function once(array $credentials = []): bool;

    /**
     * 将用户登录到应用程序中，为用户创建一个令牌。
     */
    public function login(AuthenticateInterface $user): bool;

    /**
     * 将给定的用户ID记录到应用程序中。
     */
    public function loginUsingId(int|string $id): bool;

    /**
     * 将给定的用户ID记录到应用程序中，而不需要会话或cookie。
     */
    public function onceUsingId(int|string $id): bool;

    /**
     * 将用户注销出应用程序，从而使令牌失效。
     */
    public function logout(bool $forceForever = false): void;

    /**
     * 刷新令牌。
     */
    public function refresh(bool $forceForever = false): ?string;

    /**
     * 令牌失效。
     */
    public function invalidate(bool $forceForever = false): Jwt;
}
