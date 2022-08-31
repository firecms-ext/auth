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

class Attempting
{
    /**
     * The authentication guard name.
     */
    public string $guard;

    /**
     * The credentials for the user.
     */
    public array $credentials;

    /**
     * Indicates if the user should be "remembered".
     */
    public bool $remember;

    /**
     * Create a new event instance.
     */
    public function __construct(string $guard, array $credentials, bool $remember)
    {
        $this->guard = $guard;
        $this->remember = $remember;
        $this->credentials = $credentials;
    }
}
