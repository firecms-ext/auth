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

class Failed
{
    /**
     * The authentication guard name.
     */
    public string $guard;

    /**
     * The user the attempter was trying to authenticate as.
     */
    public ?AuthenticateInterface $user;

    /**
     * The credentials provided by the attempter.
     */
    public array $credentials;

    /**
     * Create a new event instance.
     */
    public function __construct(string $guard, ?AuthenticateInterface $user, array $credentials)
    {
        $this->user = $user;
        $this->guard = $guard;
        $this->credentials = $credentials;
    }
}
