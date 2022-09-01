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

use Carbon\Carbon;
use FirecmsExt\Auth\Access\Authorizable;
use FirecmsExt\Auth\Authenticate;
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Jwt\Contracts\JwtSubjectInterface;
use Hyperf\Database\Model\SoftDeletes;
use Hyperf\DbConnection\Model\Model;
use Hyperf\ModelCache\Cacheable;
use Hyperf\ModelCache\CacheableInterface;
use Hyperf\Snowflake\Concern\Snowflake;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

/**
 * @property string $id
 * @property string $username
 * @property string $password
 * @property Carbon $created_at
 * @property Carbon $updated_at
 * @property Carbon $deleted_at
 */
class User extends Model implements AuthenticateInterface, CacheableInterface, JwtSubjectInterface
{
    use SoftDeletes;
    use Authenticate;
    use Authorizable;
    use Cacheable;
    use Snowflake;

    /**
     * 批量赋值白名单.
     * @var array
     */
    protected $fillable = [
        'username', 'password',
    ];

    /**
     * 序列化时隐藏的属性.
     * @var string[]
     */
    protected $hidden = [
        'password',
    ];

    /**
     * 属性转换.
     * @var array
     */
    protected $casts = [
        'enable' => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * 设置密码
     * @param mixed $value
     * @return void
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function setPasswordAttribute(mixed $value): void
    {
        if ($value && strlen($value) <= 30) {
            $this->attributes['password'] = bcrypt($value);
        } else {
            $this->attributes['password'] = $value;
        }
    }

    /**
     * 获取将存储在JWT主题声明中的标识符。
     */
    public function getJwtIdentifier(): string
    {
        return (string) $this->getKey();
    }

    /**
     * JWT自定义载荷.
     * @return string[]
     */
    public function getJwtCustomClaims(): array
    {
        return [
            'guard' => 'api',
        ];
    }

}
