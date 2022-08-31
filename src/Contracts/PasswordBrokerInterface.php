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

use Closure;

interface PasswordBrokerInterface
{
    /**
     * Constant representing a successfully sent reminder.
     *
     * @var string
     */
    public const RESET_LINK_SENT = 'passwords.sent';

    /**
     * Constant representing a successfully reset password.
     *
     * @var string
     */
    public const PASSWORD_RESET = 'passwords.reset';

    /**
     * Constant representing the user not found response.
     *
     * @var string
     */
    public const INVALID_USER = 'passwords.user';

    /**
     * Constant representing an invalid token.
     *
     * @var string
     */
    public const INVALID_TOKEN = 'passwords.token';

    /**
     * Constant representing a throttled reset attempt.
     *
     * @var string
     */
    public const RESET_THROTTLED = 'passwords.throttled';

    /**
     * Send a password reset link to a user.
     */
    public function sendResetLink(array $credentials): string;

    /**
     * Reset the password for the given token.
     */
    public function reset(array $credentials, Closure $callback): mixed;
}
