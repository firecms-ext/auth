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

use FirecmsExt\Auth\Annotations\Policy;
use FirecmsExt\Auth\Contracts\Access\GateInterface;
use FirecmsExt\Auth\Contracts\Access\GateManagerInterface;
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Contracts\AuthManagerInterface;
use FirecmsExt\Auth\Events\GateManagerResolved;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\AnnotationCollector;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * @method GateInterface define(string $ability, callable|string $callback) Define a new ability.
 * @method GateInterface resource(string $name, string $class, ?array $abilities = null) Define abilities for a resource.
 * @method GateInterface policy(string $class, string $policy) Define a policy class for a given class type.
 * @method GateInterface before(callable $callback) Register a callback to run before all Gate checks.
 * @method GateInterface after(callable $callback) Register a callback to run after all Gate checks.
 * @method GateInterface forUser(AuthenticateInterface $user) Get a guard instance for the given user.
 * @method Response authorize(string $ability, array|mixed $arguments = []) Determine if the given ability should be granted for the current user.
 * @method Response inspect(string $ability, array|mixed $arguments = []) Inspect the user for the given ability.
 * @method null|bool|Response raw(string $ability, array|mixed $arguments = []) Get the raw result from the authorization callback.
 * @method mixed getPolicyFor(object|string $class) Get a policy instance for a given class.
 * @method bool has(string|string[] $ability) Determine if a given ability has been defined.
 * @method bool allows(string $ability, array|mixed $arguments = []) Determine if the given ability should be granted for the current user.
 * @method bool denies(string $ability, array|mixed $arguments = []) Determine if the given ability should be denied for the current user.
 * @method bool check(iterable|string $abilities, array|mixed $arguments = []) Determine if all the given abilities should be granted for the current user.
 * @method bool any(iterable|string $abilities, array|mixed $arguments = []) Determine if any one of the given abilities should be granted for the current user.
 * @method bool none(iterable|string $abilities, array|mixed $arguments = []) Determine if all the given abilities should be denied for the current user.
 * @method array abilities() Get all the defined abilities.
 */
class GateManager implements GateManagerInterface
{
    /**
     * The container instance.
     */
    protected ContainerInterface $container;

    /**
     * The config instance.
     */
    protected ConfigInterface $config;

    /**
     * To assess gate instance.
     */
    protected ConfigInterface $gate;

    /**
     * The event dispatcher instance.
     */
    protected EventDispatcherInterface $eventDispatcher;

    /**
     * The event dispatcher instance.
     */
    protected AuthManagerInterface $auth;

    /**
     * Create a new Auth manager instance.
     */
    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->config = $container->get(ConfigInterface::class);
        $this->eventDispatcher = $container->get(EventDispatcherInterface::class);
        $this->auth = $container->get(AuthManagerInterface::class);
        $this->gate = make(Gate::class, ['userResolver' => function () {
            return call($this->auth->userResolver());
        }]);
        $this->registerPoliciesByConfig();
        $this->registerPoliciesByAnnotation();
        $this->eventDispatcher->dispatch(new GateManagerResolved($this));
    }

    /**
     * Dynamically call the default driver instance.
     *
     * @return mixed
     */
    public function __call(string $method, array $parameters)
    {
        return $this->gate->{$method}(...$parameters);
    }

    /**
     * Register the application's policies by config.
     */
    protected function registerPoliciesByConfig(): void
    {
        $policies = $this->config->get('auth.policies', []);
        foreach ($policies as $model => $policy) {
            $this->gate->policy($model, $policy);
        }
    }

    /**
     * Register the application's policies by annotation.
     */
    protected function registerPoliciesByAnnotation(): void
    {
        $policies = AnnotationCollector::getClassesByAnnotation(Policy::class);
        foreach ($policies as $policy => $annotation) {
            foreach ($annotation->models as $model) {
                $this->gate->policy($model, $policy);
            }
        }
    }
}
