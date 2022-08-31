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
namespace FirecmsExt\Auth\Exceptions;

use Exception;

class AuthenticationException extends Exception
{
    /**
     * All the guards that were checked.
     */
    protected array $guards;

    /**
     * The path the user should be redirected to.
     */
    protected string $redirectTo = '';

    /**
     * Create a new authentication exception.
     *
     * @param null|string $redirectTo
     */
    public function __construct(string $message = 'Unauthenticated.', array $guards = [], $redirectTo = null)
    {
        parent::__construct($message);

        $this->guards = $guards;
        $this->redirectTo = $redirectTo;
    }

    /**
     * Get the guards that were checked.
     */
    public function guards(): array
    {
        return $this->guards;
    }

    /**
     * Get the path the user should be redirected to.
     */
    public function redirectTo(): string
    {
        return $this->redirectTo;
    }
}
