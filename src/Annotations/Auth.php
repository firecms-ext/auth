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
namespace FirecmsExt\Auth\Annotations;

use Hyperf\Di\Annotation\AbstractAnnotation;

/**
 * @Annotation
 * @Target({"CLASS", "METHOD"})
 */
class Auth extends AbstractAnnotation
{
    /**
     * @var string[]
     */
    public array $guards;

    public bool $passable;

    public function __construct($value = null)
    {
        parent::__construct();
        if (isset($value['value'])) {
            $value['value'] = empty($value['value']) ? [] : (is_array($value['value']) ? array_unique($value['value']) : [$value['value']]);
            $this->guards = $value['value'];
        }
        if (isset($value['passable'])) {
            $this->passable = (bool) $value['passable'];
        }
    }
}
