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
namespace FirecmsExt\Auth\Events;

use FirecmsExt\Auth\Contracts\AuthManagerInterface;

class AuthManagerResolved
{
    public AuthManagerInterface $auth;

    /**
     * Create a new event instance.
     */
    public function __construct(AuthManagerInterface $auth)
    {
        $this->auth = $auth;
    }
}
