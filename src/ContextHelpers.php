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
namespace FirecmsExt\Auth;

use Hyperf\Context\Context;

trait ContextHelpers
{
    public function setContext(string $id, $value)
    {
        Context::set(static::class . '.' . $id, $value);
        return $value;
    }

    public function getContext(string $id, $default = null, $coroutineId = null)
    {
        return Context::get(static::class . '.' . $id, $default, $coroutineId);
    }
}
