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
namespace FirecmsExt\Auth\Aspect;

use FirecmsExt\Auth\Annotations\Auth;
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Contracts\AuthManagerInterface;
use FirecmsExt\Auth\Exceptions\AuthenticationException;
use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\Di\Exception\Exception;

/**
 * @Aspect
 */
class AuthAspect extends AbstractAspect
{
    public $annotations = [
        Auth::class,
    ];

    /**
     * @Inject
     */
    protected AuthManagerInterface $auth;

    /**
     * @throws AuthenticationException
     * @throws Exception
     */
    public function process(ProceedingJoinPoint $proceedingJoinPoint): mixed
    {
        $annotation = $proceedingJoinPoint->getAnnotationMetadata();

        $authAnnotation = $annotation->class[Auth::class] ?? $annotation->method[Auth::class];

        $guards = empty($authAnnotation->guards) ? [null] : $authAnnotation->guards;
        $passable = $authAnnotation->passable;

        foreach ($guards as $name) {
            $guard = $this->auth->guard($name);

            if (! $guard->user() instanceof AuthenticateInterface and ! $passable) {
                throw new AuthenticationException('Unauthenticated.', $guards);
            }
        }

        return $proceedingJoinPoint->process();
    }
}
