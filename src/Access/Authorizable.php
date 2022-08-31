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

use FirecmsExt\Auth\Contracts\Access\GateManagerInterface;
use Hyperf\Utils\ApplicationContext;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

/**
 * 授权认证
 */
trait Authorizable
{
    /**
     * Determine if the entity has the given abilities.
     *
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function can(string $abilities, array $arguments = []): bool
    {
        return ApplicationContext::getContainer()
            ->get(GateManagerInterface::class)
            ->forUser($this)
            ->check($abilities, $arguments);
    }

    /**
     * Determine if the entity does not have the given abilities.
     *
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function cannot(string $abilities, array $arguments = []): bool
    {
        return ! $this->can($abilities, $arguments);
    }
}
