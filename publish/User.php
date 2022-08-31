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
namespace App\Model;

use FirecmsExt\Auth\Access\Authorizable;
use FirecmsExt\Auth\Authenticate;
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use Hyperf\Database\Model\SoftDeletes;
use Hyperf\DbConnection\Model\Model;
use Hyperf\ModelCache\Cacheable;
use Hyperf\ModelCache\CacheableInterface;
use Hyperf\Snowflake\Concern\Snowflake;

class User extends Model implements AuthenticateInterface, CacheableInterface
{
    use SoftDeletes;
    use Authenticate;
    use Authorizable;
    use Cacheable;
    use Snowflake;

    public function setPasswordAttribute(mixed $value)
    {
        if ($value && strlen($value) <= 30) {
            $this->attributes['password'] = bcrypt($value);
        } else {
            $this->attributes['password'] = $value;
        }
    }
}
