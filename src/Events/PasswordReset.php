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

use FirecmsExt\Auth\Contracts\AuthenticateInterface;

class PasswordReset
{
    /**
     * The user.
     */
    public AuthenticateInterface $user;

    /**
     * Create a new event instance.
     */
    public function __construct(AuthenticateInterface $user)
    {
        $this->user = $user;
    }
}
