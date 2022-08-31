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
namespace FirecmsExt\Auth\Contracts\Access;

use FirecmsExt\Auth\Access\Response;
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Exceptions\AuthorizationException;
use InvalidArgumentException;

interface GateInterface
{
    /**
     * Determine if a given ability has been defined.
     *
     * @param string|string[] $ability
     */
    public function has(array|string $ability): bool;

    /**
     * Define a new ability.
     *
     * @return $this
     */
    public function define(string $ability, callable|string $callback): static;

    /**
     * Define abilities for a resource.
     *
     * @return $this
     */
    public function resource(string $name, string $class, ?array $abilities = null): static;

    /**
     * Define a policy class for a given class type.
     *
     * @return $this
     */
    public function policy(string $class, string $policy): static;

    /**
     * Register a callback to run before all Gate checks.
     *
     * @return $this
     */
    public function before(callable $callback): static;

    /**
     * Register a callback to run after all Gate checks.
     *
     * @return $this
     */
    public function after(callable $callback): static;

    /**
     * Determine if the given ability should be granted for the current user.
     */
    public function allows(string $ability, array $arguments = []): bool;

    /**
     * Determine if the given ability should be denied for the current user.
     */
    public function denies(string $ability, array $arguments = []): bool;

    /**
     * Determine if all the given abilities should be granted for the current user.
     */
    public function check(string $abilities, array $arguments = []): bool;

    /**
     * Determine if any one of the given abilities should be granted for the current user.
     */
    public function any(string $abilities, array $arguments = []): bool;

    /**
     * Determine if all the given abilities should be denied for the current user.
     */
    public function none(string $abilities, array $arguments = []): bool;

    /**
     * Determine if the given ability should be granted for the current user.
     *
     * @throws AuthorizationException
     */
    public function authorize(string $ability, array $arguments = []): Response;

    /**
     * Inspect the user for the given ability.
     */
    public function inspect(string $ability, array $arguments = []): Response;

    /**
     * Get the raw result from the authorization callback.
     *
     *@throws AuthorizationException
     */
    public function raw(string $ability, array $arguments = []): Response|bool|null;

    /**
     * Get a policy instance for a given class.
     *
     *@throws InvalidArgumentException
     */
    public function getPolicyFor(object|string $class): mixed;

    /**
     * Get a guard instance for the given user.
     */
    public function forUser(AuthenticateInterface $user): static;

    /**
     * Get all the defined abilities.
     */
    public function abilities(): array;
}
