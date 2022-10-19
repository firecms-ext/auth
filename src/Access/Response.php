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

use FirecmsExt\Auth\Exceptions\AuthorizationException;
use Hyperf\Utils\Contracts\Arrayable;

class Response implements Arrayable
{
    /**
     * Indicates whether the response was allowed.
     */
    protected bool $allowed;

    /**
     * The response message.
     */
    protected ?string $message;

    /**
     * The response code.
     */
    protected mixed $code;

    /**
     * Create a new response.
     */
    public function __construct(bool $allowed, ?string $message = null, mixed $code = null)
    {
        $this->code = $code;
        $this->allowed = $allowed;
        $this->message = $message;
    }

    /**
     * Get the string representation of the message.
     */
    public function __toString(): string
    {
        return (string) $this->message();
    }

    /**
     * Create a new "allow" Response.
     */
    public static function allow(?string $message = null, mixed $code = null): Response
    {
        return new static(true, $message, $code);
    }

    /**
     * Create a new "deny" Response.
     */
    public static function deny(?string $message = null, mixed $code = null): Response
    {
        return new static(false, $message, $code);
    }

    /**
     * Determine if the response was allowed.
     */
    public function allowed(): bool
    {
        return $this->allowed;
    }

    /**
     * Determine if the response was denied.
     */
    public function denied(): bool
    {
        return ! $this->allowed();
    }

    /**
     * Get the response message.
     */
    public function message(): ?string
    {
        return $this->message;
    }

    /**
     * Get the response code / reason.
     */
    public function code(): mixed
    {
        return $this->code;
    }

    /**
     * Throw authorization exception if response was denied.
     *
     * @return $this
     * @throws AuthorizationException
     */
    public function authorize(): Response
    {
        if ($this->denied()) {
            throw (new AuthorizationException($this->message(), $this->code()))
                ->setResponse($this);
        }

        return $this;
    }

    /**
     * Convert the response to an array.
     */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed(),
            'message' => $this->message(),
            'code' => $this->code(),
        ];
    }
}
