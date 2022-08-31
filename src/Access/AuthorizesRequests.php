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
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Exceptions\AuthorizationException;
use Hyperf\Utils\ApplicationContext;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

trait AuthorizesRequests
{
    /**
     * Authorize a given action for the current user.
     *
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function authorize(string $ability, array $arguments = []): Response
    {
        [$ability, $arguments] = $this->parseAbilityAndArguments($ability, $arguments);

        return ApplicationContext::getContainer()
            ->get(GateManagerInterface::class)
            ->authorize($ability, $arguments);
    }

    /**
     * Authorize a given action for a user.
     *
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     * @throws AuthorizationException
     */
    public function authorizeForUser(AuthenticateInterface $user, string $ability, array $arguments = []): Response
    {
        [$ability, $arguments] = $this->parseAbilityAndArguments($ability, $arguments);

        return ApplicationContext::getContainer()
            ->get(GateManagerInterface::class)
            ->forUser($user)
            ->authorize($ability, $arguments);
    }

    /**
     * Guesses the ability's name if it wasn't provided.
     */
    protected function parseAbilityAndArguments(mixed $ability, array $arguments): array
    {
        if (is_string($ability) && ! str_contains($ability, '\\')) {
            return [$ability, $arguments];
        }

        $method = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3)[2]['function'];

        return [$this->normalizeGuessedAbilityName($method), $ability];
    }

    /**
     * Normalize the ability name that has been guessed from the method name.
     */
    protected function normalizeGuessedAbilityName(string $ability): string
    {
        $map = $this->resourceAbilityMap();

        return $map[$ability] ?? $ability;
    }

    /**
     * Get the map of resource methods to ability names.
     */
    protected function resourceAbilityMap(): array
    {
        return [
            'index' => 'viewAny',
            'show' => 'view',
            'create' => 'create',
            'store' => 'create',
            'edit' => 'update',
            'update' => 'update',
            'destroy' => 'delete',
        ];
    }

    /**
     * Get the list of resource methods which do not have model parameters.
     */
    protected function resourceMethodsWithoutModels(): array
    {
        return ['index', 'create', 'store'];
    }
}
