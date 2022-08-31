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

interface GuardInterface
{
    /**
     * Determine if the current user is authenticated.
     */
    public function check(): bool;

    /**
     * Determine if the current user is a guest.
     */
    public function guest(): bool;

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticateInterface;

    /**
     * Get the ID for the currently authenticated user.
     */
    public function id(): int|string|null;

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool;

    /**
     * Set the current user.
     */
    public function setUser(AuthenticateInterface $user): static;
}
