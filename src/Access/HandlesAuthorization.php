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
namespace FirecmsExt\Auth\Access;

trait HandlesAuthorization
{
    /**
     * Create a new access response.
     */
    protected function allow(?string $message = null, mixed $code = null): Response
    {
        return Response::allow($message, $code);
    }

    /**
     * Throws an unauthorized exception.
     */
    protected function deny(?string $message = null, mixed $code = null): Response
    {
        return Response::deny($message, $code);
    }
}
