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

interface AuthManagerInterface
{
    /**
     * Get a guard instance by name.
     */
    public function guard(?string $name = null): GuardInterface;

    /**
     * Set the default guard the factory should serve.
     */
    public function shouldUse(string $name): void;
}
