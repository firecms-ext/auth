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

interface SupportsBasicAuthInterface
{
    /**
     * Attempt to authenticate using HTTP Basic Auth.
     */
    public function basic(string $field = 'email', array $extraConditions = []): void;

    /**
     * Perform a stateless HTTP Basic login attempt.
     */
    public function onceBasic(string $field = 'email', array $extraConditions = []): void;
}
