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

interface CanResetPasswordInterface
{
    /**
     * Get the e-mail address where password reset links are sent.
     */
    public function getEmailForPasswordReset(): string;

    /**
     * Send the password reset notification.
     */
    public function sendPasswordResetNotification(string $token): void;
}
