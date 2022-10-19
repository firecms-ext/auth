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

use Closure;
use Exception;
use FirecmsExt\Auth\Contracts\Access\GateInterface;
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Exceptions\AuthorizationException;
use Hyperf\Contract\ContainerInterface;
use Hyperf\Utils\Arr;
use Hyperf\Utils\Str;
use InvalidArgumentException;
use ReflectionClass;
use ReflectionException;
use ReflectionFunction;
use ReflectionParameter;

class Gate implements GateInterface
{
    use HandlesAuthorization;

    /**
     * The container instance.
     */
    protected ContainerInterface $container;

    /**
     * The user resolver callable.
     *
     * @var callable
     */
    protected $userResolver;

    /**
     * All the defined abilities.
     */
    protected array $abilities = [];

    /**
     * All the defined policies.
     */
    protected array $policies = [];

    /**
     * All the registered before callbacks.
     */
    protected array $beforeCallbacks = [];

    /**
     * All the registered after callbacks.
     */
    protected array $afterCallbacks = [];

    /**
     * All the defined abilities using class.
     * @method notation.
     */
    protected array $stringCallbacks = [];

    /**
     * The callback to be used to guess policy names.
     *
     * @var null|callable
     */
    protected $guessPolicyNamesUsingCallback;

    /**
     * Create a new gate instance.
     */
    public function __construct(
        ContainerInterface $container,
        callable $userResolver,
        array $abilities = [],
        array $policies = [],
        array $beforeCallbacks = [],
        array $afterCallbacks = [],
        ?callable $guessPolicyNamesUsingCallback = null
    ) {
        $this->policies = $policies;
        $this->container = $container;
        $this->abilities = $abilities;
        $this->userResolver = $userResolver;
        $this->afterCallbacks = $afterCallbacks;
        $this->beforeCallbacks = $beforeCallbacks;
        $this->guessPolicyNamesUsingCallback = $guessPolicyNamesUsingCallback;
    }

    /**
     * Determine if a given ability has been defined.
     *
     * @param string|string[] $ability
     */
    public function has(array|string $ability): bool
    {
        $abilities = is_array($ability) ? $ability : func_get_args();

        foreach ($abilities as $ability) {
            if (! isset($this->abilities[$ability])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Define a new ability.
     *
     * @return $this
     * @throws InvalidArgumentException
     */
    public function define(string $ability, callable|string $callback): static
    {
        if (is_array($callback) && isset($callback[0]) && is_string($callback[0])) {
            $callback = $callback[0] . '@' . $callback[1];
        }

        if (is_callable($callback)) {
            $this->abilities[$ability] = $callback;
        } elseif (is_string($callback)) {
            $this->stringCallbacks[$ability] = $callback;

            $this->abilities[$ability] = $this->buildAbilityCallback($ability, $callback);
        } else {
            throw new InvalidArgumentException("Callback must be a callable or a 'Class@method' string.");
        }

        return $this;
    }

    /**
     * Define abilities for a resource.
     *
     * @return $this
     */
    public function resource(string $name, string $class, array $abilities = null): static
    {
        $abilities = $abilities ?: [
            'viewAny' => 'viewAny',
            'view' => 'view',
            'create' => 'create',
            'update' => 'update',
            'delete' => 'delete',
        ];

        foreach ($abilities as $ability => $method) {
            $this->define($name . '.' . $ability, $class . '@' . $method);
        }

        return $this;
    }

    /**
     * Define a policy class for a given class type.
     *
     * @return $this
     */
    public function policy(string $class, string $policy): static
    {
        $this->policies[$class] = $policy;

        return $this;
    }

    /**
     * Register a callback to run before all Gate checks.
     *
     * @return $this
     */
    public function before(callable $callback): static
    {
        $this->beforeCallbacks[] = $callback;

        return $this;
    }

    /**
     * Register a callback to run after all Gate checks.
     *
     * @return $this
     */
    public function after(callable $callback): static
    {
        $this->afterCallbacks[] = $callback;

        return $this;
    }

    /**
     * Determine if the given ability should be granted for the current user.
     */
    public function allows(string $ability, array $arguments = []): bool
    {
        return $this->check($ability, $arguments);
    }

    /**
     * Determine if the given ability should be denied for the current user.
     */
    public function denies(string $ability, array $arguments = []): bool
    {
        return ! $this->allows($ability, $arguments);
    }

    /**
     * Determine if all the given abilities should be granted for the current user.
     */
    public function check(iterable|string $abilities, array $arguments = []): bool
    {
        return collect($abilities)->every(function ($ability) use ($arguments) {
            return $this->inspect($ability, $arguments)->allowed();
        });
    }

    /**
     * Determine if any one of the given abilities should be granted for the current user.
     */
    public function any(string $abilities, array $arguments = []): bool
    {
        return collect($abilities)->contains(function ($ability) use ($arguments) {
            return $this->check($ability, $arguments);
        });
    }

    /**
     * Determine if all the given abilities should be denied for the current user.
     */
    public function none(string $abilities, array $arguments = []): bool
    {
        return ! $this->any($abilities, $arguments);
    }

    /**
     * Determine if the given ability should be granted for the current user.
     *
     * @throws AuthorizationException
     */
    public function authorize(string $ability, array $arguments = []): Response
    {
        return $this->inspect($ability, $arguments)->authorize();
    }

    /**
     * Inspect the user for the given ability.
     */
    public function inspect(string $ability, array $arguments = []): Response
    {
        try {
            $result = $this->raw($ability, $arguments);

            if ($result instanceof Response) {
                return $result;
            }

            return $result ? Response::allow() : Response::deny();
        } catch (AuthorizationException $e) {
            return $e->toResponse();
        }
    }

    /**
     * Get the raw result from the authorization callback.
     *
     * @throws ReflectionException
     */
    public function raw(string $ability, array $arguments = []): Response|bool|null
    {
        $arguments = Arr::wrap($arguments);

        $user = $this->resolveUser();

        // First we will call the "before" callbacks for the Gate. If any of these give
        // back a non-null response, we will immediately return that result in order
        // to let the developers override all checks for some authorization cases.
        $result = $this->callBeforeCallbacks(
            $user,
            $ability,
            $arguments
        );

        if (is_null($result)) {
            $result = $this->callAuthCallback($user, $ability, $arguments);
        }

        // After calling the authorization callback, we will call the "after" callbacks
        // that are registered with the Gate, which allows a developer to do logging
        // if that is required for this application. Then we'll return the result.
        return $this->callAfterCallbacks(
            $user,
            $ability,
            $arguments,
            $result
        );
    }

    /**
     * Get a policy instance for a given class.
     *
     * @return null|mixed
     */
    public function getPolicyFor(object|string $class): mixed
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        if (! is_string($class)) {
            return '';
        }

        if (isset($this->policies[$class])) {
            return $this->resolvePolicy($this->policies[$class]);
        }

        foreach ($this->guessPolicyName($class) as $guessedPolicy) {
            if (class_exists($guessedPolicy)) {
                return $this->resolvePolicy($guessedPolicy);
            }
        }

        foreach ($this->policies as $expected => $policy) {
            if (is_subclass_of($class, $expected)) {
                return $this->resolvePolicy($policy);
            }
        }
        return '';
    }

    /**
     * Build a policy class instance of the given type.
     */
    public function resolvePolicy(object|string $class): mixed
    {
        return $this->container->make($class);
    }

    /**
     * Get a gate instance for the given user.
     */
    public function forUser(AuthenticateInterface $user): static
    {
        $callback = function () use ($user) {
            return $user;
        };

        return new static(
            $this->container, $callback, $this->abilities,
            $this->policies, $this->beforeCallbacks, $this->afterCallbacks,
            $this->guessPolicyNamesUsingCallback
        );
    }

    /**
     * Get all the defined abilities.
     */
    public function abilities(): array
    {
        return $this->abilities;
    }

    /**
     * Get all the defined policies.
     */
    public function policies(): array
    {
        return $this->policies;
    }

    /**
     * Specify a callback to be used to guess policy names.
     *
     * @return $this
     */
    public function guessPolicyNamesUsing(callable $callback): static
    {
        $this->guessPolicyNamesUsingCallback = $callback;

        return $this;
    }

    /**
     * Create the ability callback for a callback string.
     */
    protected function buildAbilityCallback(string $ability, string $callback): Closure
    {
        return function () use ($ability, $callback) {
            if (Str::contains($callback, '@')) {
                [$class, $method] = Str::parseCallback($callback);
            } else {
                $class = $callback;
            }

            $policy = $this->resolvePolicy($class);

            $arguments = func_get_args();

            $user = array_shift($arguments);

            $result = $this->callPolicyBefore(
                $policy,
                $user,
                $ability,
                $arguments
            );

            if (! is_null($result)) {
                return $result;
            }

            return isset($method)
                ? $policy->{$method}(...func_get_args())
                : $policy(...func_get_args());
        };
    }

    /**
     * Determine whether the callback/method can be called with the given user.
     *
     * @throws ReflectionException
     */
    protected function canBeCalledWithUser(?AuthenticateInterface $user, array|string|Closure $class, ?string $method = null): bool
    {
        if (! is_null($user)) {
            return true;
        }

        if (! is_null($method)) {
            return $this->methodAllowsGuests($class, $method);
        }

        if (is_array($class)) {
            $className = is_string($class[0]) ? $class[0] : get_class($class[0]);

            return $this->methodAllowsGuests($className, $class[1]);
        }

        return $this->callbackAllowsGuests($class);
    }

    /**
     * Determine if the given class method allows guests.
     */
    protected function methodAllowsGuests(callable|string $class, string $method): bool
    {
        try {
            $reflection = new ReflectionClass($class);

            $method = $reflection->getMethod($method);
        } catch (Exception $e) {
            return false;
        }

        if ($method) {
            $parameters = $method->getParameters();

            return isset($parameters[0]) && $this->parameterAllowsGuests($parameters[0]);
        }

        return false;
    }

    /**
     * Determine if the callback allows guests.
     *
     * @throws ReflectionException
     */
    protected function callbackAllowsGuests(callable $callback): bool
    {
        $parameters = (new ReflectionFunction($callback))->getParameters();

        return isset($parameters[0]) && $this->parameterAllowsGuests($parameters[0]);
    }

    /**
     * Determine if the given parameter allows guests.
     */
    protected function parameterAllowsGuests(ReflectionParameter $parameter): bool
    {
        return ($parameter->hasType() && $parameter->allowsNull())
            || ($parameter->isDefaultValueAvailable() && is_null($parameter->getDefaultValue()));
    }

    /**
     * Resolve and call the appropriate authorization callback.
     *
     * @throws ReflectionException
     */
    protected function callAuthCallback(?AuthenticateInterface $user, string $ability, array $arguments): Response|bool
    {
        $callback = $this->resolveAuthCallback($user, $ability, $arguments);

        return $callback($user, ...$arguments);
    }

    /**
     * Call all the before callbacks and return if a result is given.
     *
     * @throws ReflectionException
     */
    protected function callBeforeCallbacks(?AuthenticateInterface $user, string $ability, array $arguments): Response|bool|null
    {
        foreach ($this->beforeCallbacks as $before) {
            if (! $this->canBeCalledWithUser($user, $before)) {
                continue;
            }

            if (! is_null($result = $before($user, $ability, $arguments))) {
                return $result;
            }
        }
        return null;
    }

    /**
     * Call all the after callbacks with check result.
     *
     *@throws ReflectionException
     */
    protected function callAfterCallbacks(?AuthenticateInterface $user, string $ability, array $arguments, Response|bool|null $result): Response|bool|null
    {
        foreach ($this->afterCallbacks as $after) {
            if (! $this->canBeCalledWithUser($user, $after)) {
                continue;
            }

            $afterResult = $after($user, $ability, $result, $arguments);

            $result = $result instanceof Response
                ? ($result->allowed() ? $result : $afterResult)
                : ($result ?? $afterResult);
        }

        return $result;
    }

    /**
     * Resolve the callable for the given ability and arguments.
     *
     * @throws ReflectionException
     */
    protected function resolveAuthCallback(?AuthenticateInterface $user, string $ability, array $arguments): callable|bool|Closure
    {
        if (isset($arguments[0])
            && ! is_null($policy = $this->getPolicyFor($arguments[0]))
            && $callback = $this->resolvePolicyCallback($user, $ability, $arguments, $policy)) {
            return $callback;
        }

        if (isset($this->stringCallbacks[$ability])) {
            [$class, $method] = Str::parseCallback($this->stringCallbacks[$ability]);

            if ($this->canBeCalledWithUser($user, $class, $method ?: '__invoke')) {
                return $this->abilities[$ability];
            }
        }

        if (isset($this->abilities[$ability])
            && $this->canBeCalledWithUser($user, $this->abilities[$ability])) {
            return $this->abilities[$ability];
        }

        return function () {
        };
    }

    /**
     * Guess the policy name for the given class.
     */
    protected function guessPolicyName(string $class): array
    {
        if ($this->guessPolicyNamesUsingCallback) {
            return Arr::wrap(call_user_func($this->guessPolicyNamesUsingCallback, $class));
        }

        $classDirname = str_replace('/', '\\', dirname(str_replace('\\', '/', $class)));

        return [$classDirname . '\\Policy\\' . class_basename($class) . 'Policy'];
    }

    /**
     * Resolve the callback for a policy check.
     */
    protected function resolvePolicyCallback(?AuthenticateInterface $user, string $ability, array $arguments, mixed $policy): callable|bool|Closure
    {
        if (! is_callable([$policy, $this->formatAbilityToMethod($ability)])) {
            return false;
        }

        return function () use ($user, $ability, $arguments, $policy) {
            // This callback will be responsible for calling the policy's before method and
            // running this policy method if necessary. This is used to when objects are
            // mapped to policy objects in the user's configurations or on this class.
            $result = $this->callPolicyBefore(
                $policy,
                $user,
                $ability,
                $arguments
            );

            // When we receive a non-null result from this before method, we will return it
            // as the "final" results. This will allow developers to override the checks
            // in this policy to return the result for all rules defined in the class.
            if (! is_null($result)) {
                return $result;
            }

            $method = $this->formatAbilityToMethod($ability);

            return $this->callPolicyMethod($policy, $method, $user, $arguments);
        };
    }

    /**
     * Call the "before" method on the given policy, if applicable.
     *
     * @return mixed|void
     * @throws ReflectionException
     */
    protected function callPolicyBefore(mixed $policy, ?AuthenticateInterface $user, string $ability, array $arguments)
    {
        if (! method_exists($policy, 'before')) {
            return;
        }

        if ($this->canBeCalledWithUser($user, $policy, 'before')) {
            return $policy->before($user, $ability, ...$arguments);
        }
    }

    /**
     * Call the appropriate method on the given policy.
     *
     * @return mixed|void
     * @throws ReflectionException
     */
    protected function callPolicyMethod(mixed $policy, string $method, ?AuthenticateInterface $user, array $arguments)
    {
        // If this first argument is a string, that means they are passing a class name
        // to the policy. We will remove the first argument from this argument array
        // because this policy already knows what type of models it can authorize.
        if (isset($arguments[0]) && is_string($arguments[0])) {
            array_shift($arguments);
        }

        if (! is_callable([$policy, $method])) {
            return;
        }

        if ($this->canBeCalledWithUser($user, $policy, $method)) {
            return $policy->{$method}($user, ...$arguments);
        }
    }

    /**
     * Format the policy ability into a method name.
     */
    protected function formatAbilityToMethod(string $ability): string
    {
        return str_contains($ability, '-') ? Str::camel($ability) : $ability;
    }

    /**
     * Resolve the user from the user resolver.
     */
    protected function resolveUser(): mixed
    {
        return call_user_func($this->userResolver);
    }
}
