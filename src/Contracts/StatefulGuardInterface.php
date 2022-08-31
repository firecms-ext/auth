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

/**
 * Session 登录接口.
 */
interface StatefulGuardInterface extends GuardInterface
{
    /**
     * 尝试使用给定的凭证对用户进行身份验证。
     */
    public function attempt(array $credentials = [], bool $remember = false): bool;

    /**
     * 将用户登录到没有会话或cookie的应用程序。
     */
    public function once(array $credentials = []): bool;

    /**
     * 将用户登录到应用程序中。
     */
    public function login(AuthenticateInterface $user, bool $remember = false): bool;

    /**
     * 将给定的用户ID记录到应用程序中。
     */
    public function loginUsingId(string|int $id, bool $remember = false): bool;

    /**
     * 将给定的用户ID记录到应用程序中，而不需要会话或cookie。
     */
    public function onceUsingId(string|int $id): bool;

    /**
     * 确定用户是否通过“remember me” cookie 进行身份验证。
     */
    public function viaRemember(): bool;

    /**
     * 将用户退出应用程序。
     */
    public function logout(): void;
}
