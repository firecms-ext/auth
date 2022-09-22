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
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Contracts\AuthManagerInterface;
use FirecmsExt\Auth\Contracts\StatefulGuardInterface;
use FirecmsExt\Auth\Contracts\StatelessGuardInterface;
use Hyperf\Utils\ApplicationContext;

if (! function_exists('auth')) {
    /**
     * 认证助手.
     */
    function auth(?string $guard = null): StatefulGuardInterface|StatelessGuardInterface
    {
        return ApplicationContext::getContainer()
            ->get(AuthManagerInterface::class)
            ->guard($guard);
    }
}

if (! function_exists('attempt')) {
    /**
     * 用户登录.
     */
    function attempt(array $credentials, ?string $guard = null): bool
    {
        return auth($guard)->attempt($credentials);
    }
}

if (! function_exists('login')) {
    /**
     * 用户登录.
     */
    function login(AuthenticateInterface $user, ?string $guard = null): bool
    {
        return auth($guard)->login($user);
    }
}

if (! function_exists('logout')) {
    /**
     * 注销登录.
     */
    function logout(?string $guard = null): void
    {
        auth($guard)->logout();
    }
}
